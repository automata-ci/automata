use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    net::Ipv4Addr,
    num::NonZeroU16,
    str::FromStr as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use automata_ci_core::{OperationId, RunnerId};
use automata_ci_execution::{
    Cancellation, CancellationDisposition, CopyFromRequest, CopyToRequest, EnvironmentProfile,
    EnvironmentProfileId, ExecutionArgv, ExecutionCommand, ExecutionEnvironment,
    ExecutionErrorKind, ExecutionTermination, NeverCancelled, ResourceLimits, RootFilesystemPolicy,
    SandboxCustody, SandboxGeneration, SandboxProvider, SandboxState, TargetPath,
};
use automata_ci_sandbox_guest::{
    GUEST_PROTOCOL_VERSION, GuestRequest, GuestResponse, decode_frame, encode_frame,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use uuid::Uuid;

use super::*;
use crate::{
    EngineArchitecture, InstallationName,
    local_docker::engine::{
        AnchorEngineApi, CreateNetwork, EngineApi, EngineExecOutput, EngineFacts, InspectedNetwork,
        InspectedVolume, Ipv4Network, NetworkEndpoint, PreparedEngineExec,
    },
};

const JOB_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GUEST_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROFILE_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const JOB_IMAGE_ID: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const GUEST_IMAGE_ID: &str =
    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const PROXY_MANIFEST_IMAGE_ID: &str =
    "sha256:9999999999999999999999999999999999999999999999999999999999999999";
const PROXY_CONFIG_IMAGE_ID: &str =
    "sha256:8888888888888888888888888888888888888888888888888888888888888888";
const TRANSIT_NETWORK_ID: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const RESULTS_CONTAINER_ID: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const FAKE_GUEST: &[u8] = b"fake-automata-ci-sandbox-guest";

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
enum Call {
    CreateNetwork(String),
    RemoveNetwork(String),
    CreateContainer(ContainerDefinition),
    StartContainer(String),
    RemoveContainer(String),
    KillContainer(String),
    UploadArchive(String),
    CreateExec(Vec<String>, String),
    StartExec(Vec<String>),
}

#[allow(clippy::struct_excessive_bools)]
struct FakeState {
    facts: EngineFacts,
    images: BTreeMap<String, InspectedImage>,
    volumes: BTreeMap<String, InspectedVolume>,
    containers: BTreeMap<String, InspectedContainer>,
    networks: BTreeMap<String, InspectedNetwork>,
    guest_binaries: BTreeMap<String, Vec<u8>>,
    files: BTreeMap<String, Vec<u8>>,
    prepared: BTreeMap<String, (String, Vec<String>, String)>,
    lose_next_bootstrap_response: bool,
    reject_bootstrap: bool,
    bootstrap_ready: bool,
    invalid_guest_source_archive: bool,
    results_target_running: bool,
    results_readiness_empty_reads: usize,
    results_readiness_bytes: Option<Vec<u8>>,
    replace_proxy_after_empty_readiness: bool,
    results_log_reads: usize,
    next_results_transit_inspect_error: Option<EngineApiError>,
    next_results_target_error: Option<EngineApiError>,
    readiness_followup_transit_inspect_error: Option<EngineApiError>,
    readiness_followup_target_error: Option<EngineApiError>,
    replace_after_upload: bool,
    replace_after_start: bool,
    replace_after_probe: bool,
    block_next_guest_start: bool,
    replace_job_after_boundaries: Option<usize>,
    cancel_after_boundaries: Option<(usize, Arc<AtomicBool>)>,
    recreate_first_removed_after_following_remove: bool,
    first_removed_for_recreation: Option<InspectedContainer>,
    inject_daemon_default_ulimit_on_next_create: bool,
    rename_removed_container_instead: bool,
    rename_instead_of_next_remove: bool,
    mutate_container_after_inspecting_name: Option<(String, String)>,
    block_next_guest_exec: bool,
    boundary_permits: HashSet<std::thread::ThreadId>,
    lose_next_network_create_response: bool,
    calls: Vec<Call>,
    next_id: u64,
}

impl FakeState {
    fn new() -> Self {
        Self {
            facts: EngineFacts {
                engine_id: "engine-identity".to_owned(),
                server_version: "29.7.2".to_owned(),
                minimum_api_version: "1.40".to_owned(),
                maximum_api_version: "1.55".to_owned(),
                operating_system: "linux".to_owned(),
                architecture: "amd64".to_owned(),
                security_options: vec![
                    "name=cgroupns".to_owned(),
                    "name=seccomp,profile=builtin".to_owned(),
                    "name=userns".to_owned(),
                ],
                memory_limit: true,
                swap_limit: true,
                cpu_cfs_period: true,
                cpu_cfs_quota: true,
                pids_limit: true,
            },
            images: BTreeMap::new(),
            volumes: BTreeMap::new(),
            containers: BTreeMap::new(),
            networks: BTreeMap::new(),
            guest_binaries: BTreeMap::new(),
            files: BTreeMap::new(),
            prepared: BTreeMap::new(),
            lose_next_bootstrap_response: false,
            reject_bootstrap: false,
            bootstrap_ready: false,
            invalid_guest_source_archive: false,
            results_target_running: true,
            results_readiness_empty_reads: 0,
            results_readiness_bytes: None,
            replace_proxy_after_empty_readiness: false,
            results_log_reads: 0,
            next_results_transit_inspect_error: None,
            next_results_target_error: None,
            readiness_followup_transit_inspect_error: None,
            readiness_followup_target_error: None,
            replace_after_upload: false,
            replace_after_start: false,
            replace_after_probe: false,
            block_next_guest_start: false,
            replace_job_after_boundaries: None,
            cancel_after_boundaries: None,
            recreate_first_removed_after_following_remove: false,
            first_removed_for_recreation: None,
            inject_daemon_default_ulimit_on_next_create: false,
            rename_removed_container_instead: false,
            rename_instead_of_next_remove: false,
            mutate_container_after_inspecting_name: None,
            block_next_guest_exec: false,
            boundary_permits: HashSet::new(),
            lose_next_network_create_response: false,
            calls: Vec::new(),
            next_id: 1,
        }
    }

    fn object_id(&mut self) -> String {
        let id = format!("{:064x}", self.next_id);
        self.next_id += 1;
        id
    }

    fn consume_boundary(&mut self) -> Result<(), EngineApiError> {
        if !self.boundary_permits.remove(&std::thread::current().id()) {
            return Err(EngineApiError::InvalidResponse);
        }
        Ok(())
    }
}

struct FakeEngine {
    anchor_name: String,
    state: Mutex<FakeState>,
    guest_exec_blocked: AtomicBool,
    release_guest_exec: AtomicBool,
    fail_released_guest_exec: AtomicBool,
    peer_inspection_delay_millis: AtomicUsize,
    peer_inspections_in_flight: AtomicUsize,
    maximum_peer_inspections_in_flight: AtomicUsize,
    accesses: AtomicUsize,
}

struct InFlightPeerInspection<'a>(&'a AtomicUsize);

impl Drop for InFlightPeerInspection<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl FakeEngine {
    #[allow(clippy::too_many_lines)]
    fn new(installation: &Installation) -> Self {
        let mut state = FakeState::new();
        let job = job_image();
        let guest = guest_image();
        let proxy = proxy_image();
        state.images.insert(
            job.reference().to_owned(),
            inspected_image(&job, JOB_IMAGE_ID),
        );
        state.images.insert(
            guest.reference().to_owned(),
            inspected_image(&guest, GUEST_IMAGE_ID),
        );
        let mut inspected_proxy = inspected_imported_image(&proxy, PROXY_CONFIG_IMAGE_ID, vec![]);
        qualify_results_proxy_image(&mut inspected_proxy);
        state
            .images
            .insert(proxy.reference().to_owned(), inspected_proxy);
        let anchor_name = installation.anchor_volume_name().to_owned();
        state.volumes.insert(
            anchor_name.clone(),
            InspectedVolume {
                name: anchor_name.clone(),
                driver: "local".to_owned(),
                scope: "local".to_owned(),
                options: BTreeMap::new(),
                labels: BTreeMap::from([
                    ("io.automata.local.managed".to_owned(), "true".to_owned()),
                    (
                        "io.automata.local.identity-schema".to_owned(),
                        "1".to_owned(),
                    ),
                    (
                        "io.automata.local.installation-id".to_owned(),
                        installation.id().to_string(),
                    ),
                    (
                        "io.automata.local.installation-key".to_owned(),
                        installation.selector_key().to_string(),
                    ),
                    (
                        "io.automata.local.compose-project".to_owned(),
                        installation.compose_project().to_string(),
                    ),
                    (
                        "io.automata.local.resource-kind".to_owned(),
                        "identity-anchor".to_owned(),
                    ),
                ]),
            },
        );
        let transit_name = results_transit_name(installation);
        state.networks.insert(
            transit_name.clone(),
            InspectedNetwork {
                id: TRANSIT_NETWORK_ID.to_owned(),
                name: transit_name,
                driver: "bridge".to_owned(),
                scope: "local".to_owned(),
                enable_ipv4: true,
                enable_ipv6: false,
                internal: true,
                attachable: false,
                ingress: false,
                config_only: false,
                config_from: String::new(),
                ipam_driver: "default".to_owned(),
                ipam_options: BTreeMap::new(),
                ipv4_network: Ipv4Network {
                    network: Ipv4Addr::new(10, 91, 0, 0),
                    prefix: 16,
                },
                ipv4_gateway: Ipv4Addr::new(10, 91, 0, 1),
                options: BTreeMap::from([(
                    "com.docker.network.bridge.gateway_mode_ipv4".to_owned(),
                    "isolated".to_owned(),
                )]),
                labels: results_transit_labels(installation, results_plan_digest()),
                containers: BTreeMap::from([(
                    RESULTS_CONTAINER_ID.to_owned(),
                    NetworkEndpoint {
                        name: "automata-results-service".to_owned(),
                        endpoint_id:
                            "abababababababababababababababababababababababababababababababab"
                                .to_owned(),
                        mac_address: "02:42:0a:5b:00:01".to_owned(),
                        ipv4_address: Ipv4Addr::new(10, 91, 0, 2),
                        ipv4_prefix: 16,
                    },
                )]),
            },
        );
        Self {
            anchor_name,
            state: Mutex::new(state),
            guest_exec_blocked: AtomicBool::new(false),
            release_guest_exec: AtomicBool::new(false),
            fail_released_guest_exec: AtomicBool::new(false),
            peer_inspection_delay_millis: AtomicUsize::new(0),
            peer_inspections_in_flight: AtomicUsize::new(0),
            maximum_peer_inspections_in_flight: AtomicUsize::new(0),
            accesses: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> Vec<Call> {
        self.state.lock().expect("fake state").calls.clone()
    }

    fn mutate(&self, update: impl FnOnce(&mut FakeState)) {
        update(&mut self.state.lock().expect("fake state"));
    }

    fn container(&self, name: &str) -> Option<InspectedContainer> {
        self.state
            .lock()
            .expect("fake state")
            .containers
            .get(name)
            .cloned()
    }

    fn mutation_count(&self) -> usize {
        self.calls().len()
    }

    fn access_count(&self) -> usize {
        self.accesses.load(Ordering::SeqCst)
    }

    fn guest_response(&self, request: GuestRequest) -> Result<GuestResponse, EngineApiError> {
        let mut state = self.state.lock().expect("fake state");
        let response = match request {
            GuestRequest::Probe { .. } => GuestResponse::Ready {
                protocol: GUEST_PROTOCOL_VERSION,
            },
            GuestRequest::Exec { .. } => serde_json::from_value(serde_json::json!({
                "result": "exec",
                "protocol": GUEST_PROTOCOL_VERSION,
                "termination": {"kind": "exited", "code": 0},
                "records": [
                    {"stream": "stdout", "data_base64": BASE64.encode(b"ok"), "end_of_stream": false},
                    {"stream": "stdout", "data_base64": "", "end_of_stream": true},
                    {"stream": "stderr", "data_base64": "", "end_of_stream": true}
                ],
                "truncated": false
            }))
            .map_err(|_| EngineApiError::InvalidResponse)?,
            GuestRequest::WriteFile {
                path,
                content_base64,
                ..
            } => {
                let content = BASE64
                    .decode(content_base64)
                    .map_err(|_| EngineApiError::InvalidResponse)?;
                state.files.insert(path, content);
                GuestResponse::WriteFile {
                    protocol: GUEST_PROTOCOL_VERSION,
                }
            }
            GuestRequest::ReadFile { path, byte_limit, .. } => {
                let content = state
                    .files
                    .get(&path)
                    .filter(|content| content.len() <= byte_limit)
                    .cloned()
                    .ok_or(EngineApiError::InvalidResponse)?;
                GuestResponse::ReadFile {
                    protocol: GUEST_PROTOCOL_VERSION,
                    content_base64: BASE64.encode(content),
                }
            }
            _ => return Err(EngineApiError::InvalidResponse),
        };
        Ok(response)
    }
}

#[async_trait]
impl EngineApi for FakeEngine {
    async fn engine_facts(&self) -> Result<EngineFacts, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        Ok(self.state.lock().expect("fake state").facts.clone())
    }
}

#[async_trait]
impl AnchorEngineApi for FakeEngine {
    async fn inspect_volume(&self, name: &str) -> Result<Option<InspectedVolume>, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .state
            .lock()
            .expect("fake state")
            .volumes
            .get(name)
            .cloned())
    }

    async fn volume_attachments(&self, name: &str) -> Result<Vec<String>, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        if name != self.anchor_name || !state.volumes.contains_key(name) {
            return Err(EngineApiError::InvalidResponse);
        }
        state.boundary_permits.insert(std::thread::current().id());
        if let Some((remaining, cancelled)) = state.cancel_after_boundaries.take() {
            if remaining == 1 {
                cancelled.store(true, Ordering::SeqCst);
            } else {
                state.cancel_after_boundaries = Some((remaining - 1, cancelled));
            }
        }
        if let Some(remaining) = state.replace_job_after_boundaries.take() {
            if remaining == 1 {
                let id = state
                    .containers
                    .values()
                    .find(|container| container.definition.name.ends_with("-job"))
                    .map(|container| container.id.clone())
                    .ok_or(EngineApiError::InvalidResponse)?;
                replace_container(&mut state, &id)?;
            } else {
                state.replace_job_after_boundaries = Some(remaining - 1);
            }
        }
        Ok(Vec::new())
    }
}

#[async_trait]
impl SandboxEngineApi for FakeEngine {
    async fn inspect_image(
        &self,
        reference: &str,
    ) -> Result<Option<InspectedImage>, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .state
            .lock()
            .expect("fake state")
            .images
            .get(reference)
            .cloned())
    }

    async fn inspect_container(
        &self,
        name_or_id: &str,
    ) -> Result<Option<InspectedContainer>, EngineApiError> {
        let delay_millis = self.peer_inspection_delay_millis.load(Ordering::SeqCst);
        if delay_millis > 0 && name_or_id.ends_with("-results-proxy") {
            let in_flight = self
                .peer_inspections_in_flight
                .fetch_add(1, Ordering::SeqCst)
                + 1;
            let _in_flight = InFlightPeerInspection(&self.peer_inspections_in_flight);
            self.maximum_peer_inspections_in_flight
                .fetch_max(in_flight, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(
                u64::try_from(delay_millis).expect("test delay fits u64"),
            ))
            .await;
        }
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        let inspected = state
            .containers
            .get(name_or_id)
            .or_else(|| {
                state
                    .containers
                    .values()
                    .find(|container| container.id == name_or_id)
            })
            .cloned();
        if state
            .mutate_container_after_inspecting_name
            .as_ref()
            .is_some_and(|(trigger, _)| trigger == name_or_id)
        {
            let (_, target) = state
                .mutate_container_after_inspecting_name
                .take()
                .expect("guarded inspection mutation");
            state
                .containers
                .get_mut(&target)
                .ok_or(EngineApiError::InvalidResponse)?
                .isolated = false;
        }
        Ok(inspected)
    }

    async fn results_target_running(&self, id: &str) -> Result<bool, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        if let Some(error) = state.next_results_target_error.take() {
            return Err(error);
        }
        Ok(id == RESULTS_CONTAINER_ID && state.results_target_running)
    }

    async fn create_container(
        &self,
        definition: ContainerDefinition,
    ) -> Result<(), EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        state.calls.push(Call::CreateContainer(definition.clone()));
        if state.containers.contains_key(&definition.name) {
            return Err(EngineApiError::RequestFailed);
        }
        let image_id = state
            .images
            .get(&definition.image)
            .ok_or(EngineApiError::InvalidResponse)?
            .id
            .clone();
        let id = state.object_id();
        let isolated = !std::mem::take(&mut state.inject_daemon_default_ulimit_on_next_create);
        let mut realized = definition;
        for attachment in realized.networks.values_mut() {
            // Engine API v1.48 reports the requested endpoint IP and aliases
            // for a created container, but leaves NetworkID empty until start.
            attachment.network_id.clear();
        }
        state.containers.insert(
            realized.name.clone(),
            InspectedContainer {
                id,
                image_id,
                definition: realized,
                state: EngineContainerState::Created,
                // `false` represents Docker merging a daemon default ulimit
                // into an otherwise exact create request after mutation.
                isolated,
            },
        );
        Ok(())
    }

    async fn start_container(&self, id: &str) -> Result<(), EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        state.calls.push(Call::StartContainer(id.to_owned()));
        let name = state
            .containers
            .iter()
            .find_map(|(name, container)| (container.id == id).then(|| name.clone()))
            .ok_or(EngineApiError::InvalidResponse)?;
        let mut container = state
            .containers
            .remove(&name)
            .ok_or(EngineApiError::InvalidResponse)?;
        container.state = EngineContainerState::Running;
        for (network_name, attachment) in &mut container.definition.networks {
            let endpoint_id = state.object_id();
            let network = state
                .networks
                .get_mut(network_name)
                .ok_or(EngineApiError::InvalidResponse)?;
            attachment.network_id.clone_from(&network.id);
            network.containers.insert(
                container.id.clone(),
                NetworkEndpoint {
                    name: container.definition.name.clone(),
                    endpoint_id,
                    mac_address: "02:42:ac:1f:00:02".to_owned(),
                    ipv4_address: attachment.ipv4_address,
                    ipv4_prefix: network.ipv4_network.prefix,
                },
            );
        }
        state.containers.insert(name, container);
        if std::mem::take(&mut state.replace_after_start) {
            replace_container(&mut state, id)?;
        }
        Ok(())
    }

    async fn remove_container(&self, id: &str) -> Result<(), EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        state.calls.push(Call::RemoveContainer(id.to_owned()));
        let name = state
            .containers
            .iter()
            .find_map(|(name, container)| (container.id == id).then(|| name.clone()));
        let mut removed = name.and_then(|name| state.containers.remove(&name));
        if state.rename_removed_container_instead {
            if let Some(container) = removed {
                state
                    .containers
                    .insert(format!("renamed-{}", container.id), container);
            }
            return Ok(());
        }
        if state.rename_instead_of_next_remove {
            let mut retained = removed.take().ok_or(EngineApiError::InvalidResponse)?;
            let renamed = format!("{}-renamed", retained.definition.name);
            retained.definition.name.clone_from(&renamed);
            for network in state.networks.values_mut() {
                if let Some(endpoint) = network.containers.get_mut(&retained.id) {
                    endpoint.name.clone_from(&renamed);
                }
            }
            state.containers.insert(renamed, retained);
            state.rename_instead_of_next_remove = false;
        }
        if let Some(removed) = removed.as_ref() {
            for network in state.networks.values_mut() {
                network.containers.remove(&removed.id);
            }
        }
        if state.recreate_first_removed_after_following_remove {
            if let Some(mut first) = state.first_removed_for_recreation.take() {
                first.id = state.object_id();
                state
                    .containers
                    .insert(first.definition.name.clone(), first);
                state.recreate_first_removed_after_following_remove = false;
            } else {
                state.first_removed_for_recreation = removed;
            }
        }
        state.guest_binaries.remove(id);
        Ok(())
    }

    async fn kill_container(&self, id: &str) -> Result<(), EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        state.calls.push(Call::KillContainer(id.to_owned()));
        find_container_mut(&mut state, id)?.state = EngineContainerState::Exited(137);
        for network in state.networks.values_mut() {
            network.containers.remove(id);
        }
        Ok(())
    }

    async fn inspect_network(
        &self,
        id_or_name: &str,
    ) -> Result<Option<InspectedNetwork>, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        let is_results_transit = state.networks.values().any(|network| {
            network.id == TRANSIT_NETWORK_ID
                && (network.id == id_or_name || network.name == id_or_name)
        });
        if is_results_transit && let Some(error) = state.next_results_transit_inspect_error.take() {
            return Err(error);
        }
        Ok(state
            .networks
            .values()
            .find(|network| network.name == id_or_name || network.id == id_or_name)
            .cloned())
    }

    async fn create_network(&self, request: CreateNetwork) -> Result<String, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        state.calls.push(Call::CreateNetwork(request.name.clone()));
        if state.networks.contains_key(&request.name) {
            return Err(EngineApiError::RequestFailed);
        }
        let id = state.object_id();
        state.networks.insert(
            request.name.clone(),
            InspectedNetwork {
                id: id.clone(),
                name: request.name,
                driver: "bridge".to_owned(),
                scope: "local".to_owned(),
                enable_ipv4: true,
                enable_ipv6: false,
                internal: true,
                attachable: false,
                ingress: false,
                config_only: false,
                config_from: String::new(),
                ipam_driver: "default".to_owned(),
                ipam_options: BTreeMap::new(),
                ipv4_network: request.ipv4_network,
                ipv4_gateway: request.ipv4_gateway,
                options: BTreeMap::from([(
                    "com.docker.network.bridge.gateway_mode_ipv4".to_owned(),
                    "isolated".to_owned(),
                )]),
                labels: request.labels,
                containers: BTreeMap::new(),
            },
        );
        if std::mem::take(&mut state.lose_next_network_create_response) {
            Err(EngineApiError::RequestFailed)
        } else {
            Ok(id)
        }
    }

    async fn remove_network(&self, id: &str) -> Result<(), EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        state.calls.push(Call::RemoveNetwork(id.to_owned()));
        let name = state
            .networks
            .iter()
            .find_map(|(name, network)| (network.id == id).then(|| name.clone()))
            .ok_or(EngineApiError::InvalidResponse)?;
        if !state
            .networks
            .get(&name)
            .is_some_and(|network| network.containers.is_empty())
        {
            return Err(EngineApiError::RequestFailed);
        }
        state.networks.remove(&name);
        Ok(())
    }

    async fn container_logs(
        &self,
        id: &str,
        _byte_limit: usize,
    ) -> Result<Vec<u8>, EngineApiError> {
        let mut state = self.state.lock().expect("fake state");
        let is_proxy = state.containers.values().any(|container| {
            container.id == id && container.definition.name.ends_with("-results-proxy")
        });
        if !is_proxy {
            return Ok(Vec::new());
        }
        state.results_log_reads += 1;
        if state.results_readiness_empty_reads > 0 {
            state.results_readiness_empty_reads -= 1;
            if std::mem::take(&mut state.replace_proxy_after_empty_readiness) {
                replace_container(&mut state, id)?;
            }
            return Ok(Vec::new());
        }
        let readiness = state
            .results_readiness_bytes
            .clone()
            .unwrap_or_else(|| RESULTS_READY_STATUS.to_vec());
        state.next_results_transit_inspect_error =
            state.readiness_followup_transit_inspect_error.take();
        state.next_results_target_error = state.readiness_followup_target_error.take();
        Ok(readiness)
    }

    async fn download_guest_image_binary(
        &self,
        id: &str,
        byte_limit: usize,
    ) -> Result<Vec<u8>, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let state = self.state.lock().expect("fake state");
        state
            .containers
            .values()
            .find(|container| container.id == id)
            .filter(|container| {
                container.definition.name.ends_with("-guest-source")
                    && container.state == EngineContainerState::Created
            })
            .ok_or(EngineApiError::InvalidResponse)?;
        let archive = if state.invalid_guest_source_archive {
            two_file_archive(FAKE_GUEST)
        } else {
            guest_archive(FAKE_GUEST)
        }?;
        if archive.len() > byte_limit {
            return Err(EngineApiError::OutputLimit);
        }
        Ok(archive)
    }

    async fn download_sandbox_guest(
        &self,
        id: &str,
        byte_limit: usize,
    ) -> Result<Vec<u8>, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let state = self.state.lock().expect("fake state");
        let bytes = state
            .guest_binaries
            .get(id)
            .ok_or(EngineApiError::InvalidResponse)?;
        let archive = guest_archive(bytes)?;
        if archive.len() > byte_limit {
            return Err(EngineApiError::OutputLimit);
        }
        Ok(archive)
    }

    async fn upload_sandbox_archive(&self, id: &str, archive: &[u8]) -> Result<(), EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        state.calls.push(Call::UploadArchive(id.to_owned()));
        let guest = extract_uploaded_guest(archive)?;
        state.guest_binaries.insert(id.to_owned(), guest);
        if std::mem::take(&mut state.replace_after_upload) {
            replace_container(&mut state, id)?;
        }
        Ok(())
    }

    async fn create_exec(
        &self,
        container_id: &str,
        command: &[String],
        user: &str,
    ) -> Result<PreparedEngineExec, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("fake state");
        state.consume_boundary()?;
        if !state
            .containers
            .values()
            .any(|container| container.id == container_id)
        {
            return Err(EngineApiError::InvalidResponse);
        }
        state
            .calls
            .push(Call::CreateExec(command.to_vec(), user.to_owned()));
        let id = state.object_id();
        state.prepared.insert(
            id.clone(),
            (container_id.to_owned(), command.to_vec(), user.to_owned()),
        );
        Ok(PreparedEngineExec {
            id,
            container_id: container_id.to_owned(),
            command: command.to_vec(),
            user: user.to_owned(),
        })
    }

    async fn start_exec(
        &self,
        prepared: &PreparedEngineExec,
        request: &EngineExecRequest,
    ) -> Result<EngineExecOutput, EngineApiError> {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        let command = {
            let mut state = self.state.lock().expect("fake state");
            state.consume_boundary()?;
            let (container_id, command, user) = state
                .prepared
                .remove(&prepared.id)
                .ok_or(EngineApiError::InvalidResponse)?;
            if container_id != request.container_id
                || prepared.container_id != request.container_id
                || prepared.command != request.command
                || user != request.user
                || prepared.user != request.user
            {
                return Err(EngineApiError::InvalidResponse);
            }
            state.calls.push(Call::StartExec(command.clone()));
            command
        };
        if command.get(1).map(String::as_str) == Some("bootstrap-local-client") {
            let mut state = self.state.lock().expect("fake state");
            if state.reject_bootstrap {
                return Ok(EngineExecOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    exit_code: 1,
                });
            }
            state.bootstrap_ready = true;
            if std::mem::take(&mut state.lose_next_bootstrap_response) {
                return Err(EngineApiError::RequestFailed);
            }
            return Ok(EngineExecOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: 0,
            });
        }
        if !self.state.lock().expect("fake state").bootstrap_ready {
            return Err(EngineApiError::RequestFailed);
        }
        let guest_request: GuestRequest =
            decode_frame(&request.stdin).map_err(|_| EngineApiError::InvalidResponse)?;
        let block = {
            let mut state = self.state.lock().expect("fake state");
            if state.block_next_guest_start {
                state.block_next_guest_start = false;
                true
            } else if matches!(&guest_request, GuestRequest::Exec { .. })
                && state.block_next_guest_exec
            {
                state.block_next_guest_exec = false;
                true
            } else {
                false
            }
        };
        if block {
            self.guest_exec_blocked.store(true, Ordering::SeqCst);
            while !self.release_guest_exec.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            self.guest_exec_blocked.store(false, Ordering::SeqCst);
            self.release_guest_exec.store(false, Ordering::SeqCst);
            if self.fail_released_guest_exec.swap(false, Ordering::SeqCst) {
                return Err(EngineApiError::RequestFailed);
            }
        }
        let is_probe = matches!(&guest_request, GuestRequest::Probe { .. });
        let response = self.guest_response(guest_request)?;
        if is_probe {
            let mut state = self.state.lock().expect("fake state");
            if std::mem::take(&mut state.replace_after_probe) {
                replace_container(&mut state, &request.container_id)?;
            }
        }
        let stdout = encode_frame(&response).map_err(|_| EngineApiError::InvalidResponse)?;
        if stdout.len() > request.stdout_limit {
            return Err(EngineApiError::OutputLimit);
        }
        Ok(EngineExecOutput {
            stdout,
            stderr: Vec::new(),
            exit_code: 0,
        })
    }
}

fn find_container_mut<'a>(
    state: &'a mut FakeState,
    id: &str,
) -> Result<&'a mut InspectedContainer, EngineApiError> {
    state
        .containers
        .values_mut()
        .find(|container| container.id == id)
        .ok_or(EngineApiError::InvalidResponse)
}

fn replace_container(state: &mut FakeState, id: &str) -> Result<(), EngineApiError> {
    let (name, mut replacement) = state
        .containers
        .iter()
        .find(|(_, container)| container.id == id)
        .map(|(name, container)| (name.clone(), container.clone()))
        .ok_or(EngineApiError::InvalidResponse)?;
    let replacement_id = state.object_id();
    replacement.id = replacement_id.clone();
    let attached_networks = state
        .networks
        .iter()
        .filter(|(_, network)| network.containers.contains_key(id))
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    for network_name in attached_networks {
        let mut endpoint = state
            .networks
            .get_mut(&network_name)
            .and_then(|network| network.containers.remove(id))
            .ok_or(EngineApiError::InvalidResponse)?;
        endpoint.endpoint_id = state.object_id();
        state
            .networks
            .get_mut(&network_name)
            .ok_or(EngineApiError::InvalidResponse)?
            .containers
            .insert(replacement_id.clone(), endpoint);
    }
    state.containers.insert(name, replacement);
    if let Some(guest) = state.guest_binaries.remove(id) {
        state.guest_binaries.insert(replacement_id, guest);
    }
    Ok(())
}

fn guest_archive(bytes: &[u8]) -> Result<Vec<u8>, EngineApiError> {
    archive_with_files(&[("automata-ci-sandbox-guest", bytes)])
}

fn two_file_archive(bytes: &[u8]) -> Result<Vec<u8>, EngineApiError> {
    archive_with_files(&[
        ("automata-ci-sandbox-guest", bytes),
        ("foreign", b"collision"),
    ])
}

fn archive_with_files(files: &[(&str, &[u8])]) -> Result<Vec<u8>, EngineApiError> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o555);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(u64::try_from(bytes.len()).map_err(|_| EngineApiError::OutputLimit)?);
        header
            .set_path(path)
            .map_err(|_| EngineApiError::InvalidResponse)?;
        header.set_cksum();
        builder
            .append(&header, *bytes)
            .map_err(|_| EngineApiError::InvalidResponse)?;
    }
    builder
        .into_inner()
        .map_err(|_| EngineApiError::InvalidResponse)
}

fn extract_uploaded_guest(archive: &[u8]) -> Result<Vec<u8>, EngineApiError> {
    let mut tar = tar::Archive::new(archive);
    let mut guest = None;
    for entry in tar.entries().map_err(|_| EngineApiError::InvalidResponse)? {
        let mut entry = entry.map_err(|_| EngineApiError::InvalidResponse)?;
        if entry
            .path()
            .map_err(|_| EngineApiError::InvalidResponse)?
            .as_ref()
            == std::path::Path::new("automata/bin/automata-ci-sandbox-guest")
        {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes)
                .map_err(|_| EngineApiError::InvalidResponse)?;
            guest = Some(bytes);
        }
    }
    guest.ok_or(EngineApiError::InvalidResponse)
}

struct Fixture {
    provider: LocalDockerProvider,
    engine: Arc<FakeEngine>,
    installation: Installation,
}

impl Fixture {
    fn new() -> Self {
        let installation = Installation::verified(
            InstallationName::new("test").expect("installation name"),
            InstallationId::parse_canonical("00000000-0000-4000-8000-000000000001")
                .expect("canonical test installation ID"),
        );
        let engine = Arc::new(FakeEngine::new(&installation));
        let provider = LocalDockerProvider::with_test_engine(
            PinnedDockerEngine::for_test(EngineArchitecture::Amd64, engine.clone()),
            engine.clone(),
            installation.clone(),
            guest_image(),
            GUEST_IMAGE_ID.to_owned(),
            verified_results_transport(&installation),
            RunnerId::from_uuid(Uuid::from_u128(2)),
        );
        Self {
            provider,
            engine,
            installation,
        }
    }

    fn reopen_provider(&self) -> LocalDockerProvider {
        LocalDockerProvider::with_test_engine(
            PinnedDockerEngine::for_test(EngineArchitecture::Amd64, self.engine.clone()),
            self.engine.clone(),
            self.installation.clone(),
            guest_image(),
            GUEST_IMAGE_ID.to_owned(),
            verified_results_transport(&self.installation),
            RunnerId::from_uuid(Uuid::from_u128(2)),
        )
    }
}

fn inspected_image(image: &ImmutableImage, id: &str) -> InspectedImage {
    InspectedImage {
        id: id.to_owned(),
        repo_tags: Vec::new(),
        repo_digests: vec![image.reference().to_owned()],
        operating_system: "linux".to_owned(),
        architecture: "amd64".to_owned(),
        declared_volumes: Vec::new(),
        declared_exposed_ports: Vec::new(),
        has_healthcheck: false,
        labels: BTreeMap::new(),
        environment_names: Vec::new(),
        default_path_only: false,
        user: String::new(),
        entrypoint: Vec::new(),
        command: Vec::new(),
        working_directory: String::new(),
    }
}

fn job_image() -> ImmutableImage {
    ImmutableImage::new(format!("registry.example/automata/job@sha256:{JOB_DIGEST}"))
        .expect("job image")
}

fn guest_image() -> ImmutableImage {
    ImmutableImage::new(format!(
        "registry.example/automata/guest@sha256:{GUEST_DIGEST}"
    ))
    .expect("guest image")
}

fn proxy_image() -> LocalImportedImage {
    LocalImportedImage::new(PROXY_CONFIG_IMAGE_ID, PROXY_MANIFEST_IMAGE_ID).expect("proxy image")
}

fn inspected_imported_image(
    image: &LocalImportedImage,
    id: &str,
    repo_digests: Vec<String>,
) -> InspectedImage {
    InspectedImage {
        id: id.to_owned(),
        repo_tags: vec![image.reference().to_owned()],
        repo_digests,
        operating_system: "linux".to_owned(),
        architecture: "amd64".to_owned(),
        declared_volumes: Vec::new(),
        declared_exposed_ports: Vec::new(),
        has_healthcheck: false,
        labels: BTreeMap::new(),
        environment_names: Vec::new(),
        default_path_only: false,
        user: String::new(),
        entrypoint: Vec::new(),
        command: Vec::new(),
        working_directory: String::new(),
    }
}

fn qualify_results_proxy_image(image: &mut InspectedImage) {
    image.environment_names = vec!["PATH".to_owned()];
    image.default_path_only = true;
    image.user = RESULTS_PROXY_USER.to_owned();
    image.entrypoint = vec![RESULTS_PROXY_ENTRYPOINT.to_owned()];
    image.working_directory = "/".to_owned();
    image.labels.insert(
        RESULTS_PROXY_IMAGE_PROTOCOL_LABEL.to_owned(),
        RESULTS_PROXY_IMAGE_PROTOCOL_VERSION.to_owned(),
    );
}

fn proxy_manifest_digest_reference() -> String {
    format!("automata.local/automata-ci-service-proxy@{PROXY_MANIFEST_IMAGE_ID}")
}

fn results_plan_digest() -> Sha256Digest {
    Sha256Digest::from_bytes([0x77; 32])
}

fn verified_results_transport(installation: &Installation) -> VerifiedResultsTransport {
    VerifiedResultsTransport {
        requested: LocalDockerResultsTransport::new(
            proxy_image(),
            results_plan_digest(),
            TRANSIT_NETWORK_ID,
            RESULTS_CONTAINER_ID,
            Ipv4Addr::new(10, 91, 0, 2),
        )
        .expect("transport"),
        transit_name: results_transit_name(installation),
        transit_network: Ipv4Network {
            network: Ipv4Addr::new(10, 91, 0, 0),
            prefix: 16,
        },
        transit_gateway: Ipv4Addr::new(10, 91, 0, 1),
        proxy_image_id: PROXY_CONFIG_IMAGE_ID.to_owned(),
        proxy_image_labels: BTreeMap::from([(
            RESULTS_PROXY_IMAGE_PROTOCOL_LABEL.to_owned(),
            RESULTS_PROXY_IMAGE_PROTOCOL_VERSION.to_owned(),
        )]),
    }
}

fn sandbox_spec() -> SandboxSpec {
    sandbox_spec_with_resources(ResourceLimits::new(256 * 1024 * 1024, 2_000, 128).expect("limits"))
}

fn sandbox_spec_with_resources(resources: ResourceLimits) -> SandboxSpec {
    sandbox_spec_with_custody_and_resources(
        SandboxCustody::Job {
            runner_id: RunnerId::from_uuid(Uuid::from_u128(2)),
            slot_ordinal: NonZeroU16::new(3).expect("slot"),
        },
        resources,
    )
}

fn sandbox_spec_for_job_slot(operation: u128, slot: u16) -> SandboxSpec {
    sandbox_spec_with_identity_and_resources(
        operation,
        7,
        SandboxCustody::Job {
            runner_id: RunnerId::from_uuid(Uuid::from_u128(2)),
            slot_ordinal: NonZeroU16::new(slot).expect("slot"),
        },
        ResourceLimits::new(256 * 1024 * 1024, 2_000, 128).expect("limits"),
    )
}

fn sandbox_spec_with_custody_and_resources(
    custody: SandboxCustody,
    resources: ResourceLimits,
) -> SandboxSpec {
    sandbox_spec_with_identity_and_resources(1, 7, custody, resources)
}

fn sandbox_spec_with_identity_and_resources(
    operation: u128,
    generation: u64,
    custody: SandboxCustody,
    resources: ResourceLimits,
) -> SandboxSpec {
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("example.local/linux").expect("profile id"),
        Sha256Digest::from_str(PROFILE_DIGEST).expect("profile digest"),
    );
    let environment = automata_ci_execution::SandboxEnvironment::new(
        profile,
        job_image(),
        ExecutionArgv::new(
            TargetPath::posix("/bin/sleep").expect("program"),
            vec!["infinity".to_owned()],
        )
        .expect("keepalive"),
        TargetPath::posix("/workspace").expect("profile workspace"),
        ExecutionEnvironment::empty(),
    )
    .expect("environment");
    SandboxSpec::new(
        OperationId::from_uuid(Uuid::from_u128(operation)),
        SandboxGeneration::new(generation).expect("generation"),
        custody,
        environment,
        TargetPath::posix("/workspace/repository").expect("workspace"),
        NetworkPolicy::PrivateEgress,
        RootFilesystemPolicy::Writable,
        resources,
    )
    .with_privilege(SandboxPrivilegePolicy::Administrator)
}

fn sandbox_spec_with_workspace(workspace: TargetPath) -> SandboxSpec {
    let spec = sandbox_spec();
    SandboxSpec::new(
        spec.operation_id(),
        spec.generation(),
        spec.custody(),
        spec.profile().clone(),
        workspace,
        spec.network(),
        spec.root_filesystem(),
        spec.resources(),
    )
    .with_privilege(spec.privilege())
}

fn true_command(spec: &SandboxSpec, operation: u128) -> ExecutionCommand {
    ExecutionCommand::new(
        OperationId::from_uuid(Uuid::from_u128(operation)),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        spec.workspace().clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(2),
        1024,
    )
    .expect("command")
}

#[derive(Clone, Debug)]
struct ToggleCancellation {
    cancelled: Arc<AtomicBool>,
    observations: Arc<AtomicUsize>,
}

impl ToggleCancellation {
    fn active() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            observations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

impl Cancellation for ToggleCancellation {
    fn disposition(&self) -> CancellationDisposition {
        self.observations.fetch_add(1, Ordering::SeqCst);
        if self.cancelled.load(Ordering::SeqCst) {
            CancellationDisposition::Terminate
        } else {
            CancellationDisposition::Active
        }
    }
}

fn wait_for_test(mut predicate: impl FnMut() -> bool, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(Instant::now() < deadline, "{message}");
        std::thread::yield_now();
    }
}

const fn engine_failure_categories() -> [(EngineApiError, ProviderErrorKind); 3] {
    [
        (
            EngineApiError::RequestFailed,
            ProviderErrorKind::AdapterUnavailable,
        ),
        (
            EngineApiError::InvalidResponse,
            ProviderErrorKind::BackendRejected,
        ),
        (
            EngineApiError::OutputLimit,
            ProviderErrorKind::OutputLimitExceeded,
        ),
    ]
}

fn assert_exact_create_recovery(
    fixture: &Fixture,
    spec: &SandboxSpec,
    error: &ProviderError,
) -> SandboxHandle {
    let names = ResourceNames::for_spec(&fixture.installation, spec).expect("resource names");
    let expected = names
        .handle(&fixture.provider.inner.provider_id)
        .expect("recovery handle");
    assert_eq!(error.outcome(), OperationOutcome::Uncertain);
    assert_eq!(error.recovery_handle(), Some(&expected));
    expected
}

fn destroy_create_recovery(fixture: &Fixture, spec: &SandboxSpec, error: &ProviderError) {
    let handle = assert_exact_create_recovery(fixture, spec, error);
    let request = DestroySandbox::new(
        OperationId::from_uuid(Uuid::from_u128(0xffff)),
        handle,
        spec.generation(),
        spec.custody(),
    );
    assert_eq!(
        fixture
            .provider
            .destroy(&request, &NeverCancelled)
            .expect("exact recovery cleanup"),
        DestroyDisposition::Destroyed
    );
    let names = ResourceNames::for_spec(&fixture.installation, spec).expect("resource names");
    let state = fixture.engine.state.lock().expect("fake state");
    assert!(!state.networks.contains_key(&names.results_front));
    assert!(!state.containers.contains_key(&names.helper));
    assert!(!state.containers.contains_key(&names.job));
    assert!(!state.containers.contains_key(&names.results_proxy));
}

#[test]
fn provider_advertises_the_attenuated_administrator_user_namespace_boundary() {
    let fixture = Fixture::new();
    let capabilities = fixture.provider.capabilities();

    assert!(capabilities.supports(SandboxCapability::Administrator));
    assert!(capabilities.supports(SandboxCapability::UserNamespace));
    assert!(!capabilities.supports(SandboxCapability::HostIdentity));
    assert!(!capabilities.supports(SandboxCapability::HostFilesystem));
    assert!(!capabilities.supports(SandboxCapability::HostNetwork));
}

#[tokio::test]
async fn configured_binding_becomes_verified_only_after_anchor_resolution() {
    let fixture = Fixture::new();
    let binding = crate::InstallationBinding::new(
        fixture.installation.name().clone(),
        fixture.installation.id(),
    );
    assert_eq!(
        super::engine::resolve_installation_binding(fixture.engine.as_ref(), &binding)
            .await
            .expect("matching anchor produces verified installation"),
        fixture.installation
    );

    let mismatched = crate::InstallationBinding::new(
        binding.name().clone(),
        InstallationId::parse_canonical("00000000-0000-4000-8000-000000000002")
            .expect("canonical mismatched ID"),
    );
    assert_eq!(
        super::engine::resolve_installation_binding(fixture.engine.as_ref(), &mismatched)
            .await
            .expect_err("configuration assertion is not verification")
            .code(),
        LocalDockerErrorCode::InvalidIdentityAnchor
    );
}

#[test]
fn daemon_security_option_drift_invalidates_the_pinned_provider() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create before daemon drift");
    fixture.engine.mutate(|state| {
        state
            .facts
            .security_options
            .push("name=no-new-privileges".to_owned());
    });

    let error = fixture
        .provider
        .inspect(record.handle(), &NeverCancelled)
        .expect_err("changed daemon security options must invalidate the pin");
    assert_eq!(error.kind(), ProviderErrorKind::AdapterUnavailable);
}

#[test]
fn resource_controller_drift_invalidates_the_provider_before_mutation() {
    for controller in 0..5 {
        let fixture = Fixture::new();
        fixture.engine.mutate(|state| match controller {
            0 => state.facts.memory_limit = false,
            1 => state.facts.swap_limit = false,
            2 => state.facts.cpu_cfs_period = false,
            3 => state.facts.cpu_cfs_quota = false,
            4 => state.facts.pids_limit = false,
            _ => unreachable!(),
        });
        let error = fixture
            .provider
            .create(&sandbox_spec(), &NeverCancelled)
            .expect_err("controller drift must invalidate the pin");
        assert_eq!(error.kind(), ProviderErrorKind::AdapterUnavailable);
        assert_eq!(fixture.engine.mutation_count(), 0);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn lifecycle_uses_zero_volumes_and_exact_replay_cleanup() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    assert_eq!(record.state(), SandboxState::Running);
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job container");
    let proxy = fixture
        .engine
        .container(&names.results_proxy)
        .expect("Results proxy container");
    let state = fixture.engine.state.lock().expect("state");
    let front = state
        .networks
        .get(&names.results_front)
        .expect("per-sandbox Results front");
    assert!(front.internal);
    assert_eq!(
        front
            .options
            .get("com.docker.network.bridge.gateway_mode_ipv4"),
        Some(&"isolated".to_owned())
    );
    assert_eq!(job.definition.networks.len(), 1);
    assert_eq!(proxy.definition.networks.len(), 2);
    assert_eq!(
        proxy
            .definition
            .networks
            .get(&names.results_front)
            .expect("proxy front")
            .aliases,
        [RESULTS_ALIAS]
    );
    assert_eq!(front.containers.len(), 2);
    let transit = state
        .networks
        .values()
        .find(|network| network.id == TRANSIT_NETWORK_ID)
        .expect("shared transit");
    assert_eq!(transit.containers.len(), 2);
    assert!(transit.containers.contains_key(RESULTS_CONTAINER_ID));
    drop(state);
    assert_eq!(
        job.definition.tmpfs,
        BTreeMap::from([
            (
                "/workspace/repository".to_owned(),
                job_tmpfs_options(256 * 1024 * 1024),
            ),
            (
                LOCAL_CONTROL_DIRECTORY.to_owned(),
                guest_control_tmpfs_options(),
            ),
        ])
    );
    assert!(fixture.engine.container(&names.helper).is_none());
    assert_eq!(
        fixture.engine.state.lock().expect("state").volumes.len(),
        1,
        "the installation anchor is the only volume"
    );
    let calls = fixture.engine.calls();
    let source = calls
        .iter()
        .find_map(|call| match call {
            Call::CreateContainer(definition) if definition.name.ends_with("-guest-source") => {
                Some(definition)
            }
            _ => None,
        })
        .expect("guest source definition");
    assert_eq!(source.entrypoint, LOCAL_DOCKER_GUEST_IMAGE_BINARY);
    assert!(source.arguments.is_empty());
    assert!(source.tmpfs.is_empty());
    assert_eq!(source.user, guest_client_user());
    assert!(source.read_only_root);
    assert!(
        calls
            .iter()
            .any(|call| matches!(call, Call::UploadArchive(_)))
    );
    assert!(calls.iter().any(|call| matches!(
        call,
        Call::CreateExec(command, user)
            if command == &[LOCAL_DOCKER_SANDBOX_GUEST_BINARY, "bootstrap-local-client"]
                && user == &guest_seal_user()
    )));
    assert!(calls.iter().all(|call| {
        !matches!(call, Call::StartContainer(id) if id != &job.id && id != &proxy.id)
    }));
    assert!(calls.iter().any(|call| matches!(
        call,
        Call::CreateExec(command, user)
            if command == &[LOCAL_CONTROL_CLIENT, "local-client"]
                && user == &guest_client_user()
    )));

    let starts_before = calls
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    let replay = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("exact replay");
    assert_eq!(replay, record);
    let starts_after = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    assert_eq!(starts_before, starts_after, "running replay never restarts");

    let reopened = fixture.reopen_provider();
    let inspection = reopened
        .inspect(record.handle(), &NeverCancelled)
        .expect("inspect");
    assert_eq!(inspection.state(), SandboxState::Running);
    assert_eq!(inspection.custody(), spec.custody());
    let endpoint = reopened
        .attach(record.handle(), &NeverCancelled)
        .expect("attach");
    let command = ExecutionCommand::new(
        OperationId::from_uuid(Uuid::from_u128(10)),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        spec.workspace().clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(2),
        1024,
    )
    .expect("command");
    let output = endpoint
        .exec(
            &command,
            &NeverCancelled,
            automata_ci_execution::discard_execution_output(),
        )
        .expect("exec");
    assert_eq!(output.termination(), ExecutionTermination::Exited(0));
    assert_eq!(output.stdout(), b"ok");
    let path = TargetPath::posix("/workspace/repository/result.txt").expect("path");
    endpoint
        .copy_to(
            &CopyToRequest::new(
                OperationId::from_uuid(Uuid::from_u128(11)),
                path.clone(),
                b"artifact".to_vec(),
            )
            .expect("copy request"),
            &NeverCancelled,
        )
        .expect("copy to");
    assert_eq!(
        endpoint
            .copy_from(
                &CopyFromRequest::new(OperationId::from_uuid(Uuid::from_u128(12)), path, 64)
                    .expect("read request"),
                &NeverCancelled,
            )
            .expect("copy from"),
        b"artifact"
    );
    drop(endpoint);

    let destroy = DestroySandbox::new(
        OperationId::from_uuid(Uuid::from_u128(13)),
        record.handle().clone(),
        record.generation(),
        spec.custody(),
    );
    assert_eq!(
        reopened
            .destroy(&destroy, &NeverCancelled)
            .expect("destroy"),
        DestroyDisposition::Destroyed
    );
    assert_eq!(
        reopened
            .destroy(&destroy, &NeverCancelled)
            .expect("destroy replay"),
        DestroyDisposition::AlreadyAbsent
    );
    assert!(
        fixture
            .engine
            .state
            .lock()
            .expect("state")
            .containers
            .is_empty()
    );
    let state = fixture.engine.state.lock().expect("state");
    assert!(!state.networks.contains_key(&names.results_front));
    let transit = state
        .networks
        .values()
        .find(|network| network.id == TRANSIT_NETWORK_ID)
        .expect("shared transit remains lifecycle-owned");
    assert_eq!(
        transit.containers.keys().cloned().collect::<Vec<_>>(),
        [RESULTS_CONTAINER_ID.to_owned()]
    );
}

#[test]
fn raw_endpoint_duplicate_operation_ids_are_attempted_twice() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach");
    let request = true_command(&spec, 40);
    let raw_guest_attempts = || {
        fixture
            .engine
            .calls()
            .iter()
            .filter(|call| {
                matches!(
                    call,
                    Call::StartExec(command)
                        if command == &[LOCAL_CONTROL_CLIENT, "local-client"]
                )
            })
            .count()
    };
    let before = raw_guest_attempts();

    endpoint
        .exec(
            &request,
            &NeverCancelled,
            automata_ci_execution::discard_execution_output(),
        )
        .expect("first raw attempt");
    endpoint
        .exec(
            &request,
            &NeverCancelled,
            automata_ci_execution::discard_execution_output(),
        )
        .expect("second raw attempt");

    assert_eq!(raw_guest_attempts() - before, 2);
    fixture
        .provider
        .destroy(
            &DestroySandbox::new(
                OperationId::from_uuid(Uuid::from_u128(41)),
                record.handle().clone(),
                record.generation(),
                spec.custody(),
            ),
            &NeverCancelled,
        )
        .expect("destroy");
}

#[test]
fn ambiguous_bootstrap_response_stops_and_removes_the_unproven_container() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.lose_next_bootstrap_response = true);
    let spec = sandbox_spec();
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("ambiguous bootstrap is never accepted");
    assert_eq!(error.kind(), ProviderErrorKind::AdapterUnavailable);
    assert_exact_create_recovery(&fixture, &spec, &error);
    assert!(fixture.engine.container(&names.job).is_none());
    let calls = fixture.engine.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(
                call,
                Call::CreateExec(command, user)
                    if command == &[LOCAL_DOCKER_SANDBOX_GUEST_BINARY, "bootstrap-local-client"]
                        && user == &guest_seal_user()
            ))
            .count(),
        1
    );
    destroy_create_recovery(&fixture, &spec, &error);
}

#[test]
fn attach_probe_start_failure_stops_exact_job_and_never_restarts_it() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let starts_before = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    fixture
        .engine
        .mutate(|state| state.block_next_guest_start = true);
    fixture
        .engine
        .fail_released_guest_exec
        .store(true, Ordering::SeqCst);

    let error = std::thread::scope(|scope| {
        let call = scope.spawn(|| fixture.provider.attach(record.handle(), &NeverCancelled));
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "attach probe did not reach the controlled start",
        );
        fixture
            .engine
            .release_guest_exec
            .store(true, Ordering::SeqCst);
        call.join()
            .expect("attach thread")
            .expect_err("uncertain probe start")
    });
    assert_eq!(error.kind(), ProviderErrorKind::AdapterUnavailable);
    assert_eq!(
        fixture.engine.container(&names.job).expect("job").state,
        EngineContainerState::Exited(137)
    );
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .any(|call| matches!(call, Call::KillContainer(id) if id == &job.id))
    );
    let replay = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("exited job is never restarted");
    assert_eq!(replay.kind(), ProviderErrorKind::InvalidState);
    let starts_after = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    assert_eq!(starts_after, starts_before);
}

#[test]
fn cancelled_in_flight_attach_probe_stops_exact_job_before_returning() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    fixture
        .engine
        .mutate(|state| state.block_next_guest_start = true);
    let cancellation = ToggleCancellation::active();

    let error = std::thread::scope(|scope| {
        let call = scope.spawn(|| fixture.provider.attach(record.handle(), &cancellation));
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "attach probe did not reach the controlled start",
        );
        cancellation.cancel();
        wait_for_test(
            || call.is_finished(),
            "cancelled attach did not stop the exact job within the bound",
        );
        call.join()
            .expect("attach thread")
            .expect_err("cancelled probe start")
    });
    fixture
        .engine
        .guest_exec_blocked
        .store(false, Ordering::SeqCst);
    assert_eq!(error.kind(), ProviderErrorKind::Cancelled);
    assert_eq!(
        fixture.engine.container(&names.job).expect("job").state,
        EngineContainerState::Exited(137)
    );
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .any(|call| matches!(call, Call::KillContainer(id) if id == &job.id))
    );
}

#[test]
fn unready_bootstrap_is_destroyed_and_never_adopted_or_retried() {
    let fixture = Fixture::new();
    fixture.engine.mutate(|state| state.reject_bootstrap = true);
    let spec = sandbox_spec();
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("unready broker fails closed");
    assert_eq!(error.kind(), ProviderErrorKind::BackendRejected);
    assert_exact_create_recovery(&fixture, &spec, &error);
    assert!(fixture.engine.container(&names.job).is_none());
    let calls = fixture.engine.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(
                call,
                Call::CreateExec(command, user)
                    if command == &[LOCAL_DOCKER_SANDBOX_GUEST_BINARY, "bootstrap-local-client"]
                        && user == &guest_seal_user()
            ))
            .count(),
        1
    );
    assert!(
        calls
            .iter()
            .any(|call| matches!(call, Call::KillContainer(_)))
    );
    assert!(
        calls
            .iter()
            .any(|call| matches!(call, Call::RemoveContainer(_)))
    );
    destroy_create_recovery(&fixture, &spec, &error);
}

#[test]
fn exited_job_is_never_restarted() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job_id = fixture.engine.container(&names.job).expect("job").id;
    fixture.engine.mutate(|state| {
        find_container_mut(state, &job_id).expect("job").state = EngineContainerState::Exited(0);
        for network in state.networks.values_mut() {
            network.containers.remove(&job_id);
        }
    });
    let starts_before = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job_id))
        .count();
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("stopped create replay must fail");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidState);
    let starts_after = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job_id))
        .count();
    assert_eq!(starts_before, starts_after);
}

#[test]
fn endpoint_cancellation_is_prechecked_then_kills_only_the_exact_running_container() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");

    let mutations_before_pre_cancel = fixture.engine.mutation_count();
    let pre_cancelled = ToggleCancellation::active();
    pre_cancelled.cancel();
    let error = endpoint
        .exec(
            &true_command(&spec, 300),
            &pre_cancelled,
            automata_ci_execution::discard_execution_output(),
        )
        .expect_err("pre-cancelled exec");
    assert_eq!(error.kind(), ExecutionErrorKind::Cancelled);
    assert_eq!(fixture.engine.mutation_count(), mutations_before_pre_cancel);
    assert_eq!(
        fixture.engine.container(&names.job).expect("job").state,
        EngineContainerState::Running
    );

    fixture
        .engine
        .mutate(|state| state.block_next_guest_start = true);
    let starts_before = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    let cancellation = ToggleCancellation::active();
    let request = true_command(&spec, 301);
    let error = std::thread::scope(|scope| {
        let call = scope.spawn(|| {
            endpoint.exec(
                &request,
                &cancellation,
                automata_ci_execution::discard_execution_output(),
            )
        });
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "endpoint did not reach the controlled guest start",
        );
        cancellation.cancel();
        wait_for_test(
            || call.is_finished(),
            "cancelled endpoint did not stop the exact job within the bound",
        );
        call.join()
            .expect("endpoint thread")
            .expect_err("mid-exec cancellation")
    });
    fixture
        .engine
        .guest_exec_blocked
        .store(false, Ordering::SeqCst);
    assert_eq!(error.kind(), ExecutionErrorKind::Cancelled);
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .any(|call| matches!(call, Call::KillContainer(id) if id == &job.id))
    );
    assert_eq!(
        fixture
            .engine
            .container(&names.job)
            .expect("stopped job")
            .state,
        EngineContainerState::Exited(137)
    );
    let starts_after = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    assert_eq!(starts_after, starts_before, "cancellation never restarts");

    let replay = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("exited sandbox is not restartable");
    assert_eq!(replay.kind(), ProviderErrorKind::InvalidState);
    let final_starts = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    assert_eq!(final_starts, starts_before);
}

#[test]
fn queued_endpoint_cancellation_returns_before_holder_release_and_mutates_nothing() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let first = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("first endpoint");
    let second = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("second endpoint");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let command = |operation| {
        ExecutionCommand::new(
            OperationId::from_uuid(Uuid::from_u128(operation)),
            ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
                .expect("argv"),
            spec.workspace().clone(),
            ExecutionEnvironment::empty(),
            Duration::from_secs(2),
            1024,
        )
        .expect("command")
    };
    let first_command = command(302);
    let second_command = command(303);
    fixture
        .engine
        .mutate(|state| state.block_next_guest_exec = true);
    let cancellation = ToggleCancellation::active();

    std::thread::scope(|scope| {
        let first_call = scope.spawn(|| {
            first.exec(
                &first_command,
                &NeverCancelled,
                automata_ci_execution::discard_execution_output(),
            )
        });
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "first endpoint operation did not reach the controlled exec",
        );

        let queued_cancellation = cancellation.clone();
        let second_call = scope.spawn(move || {
            second.exec(
                &second_command,
                &queued_cancellation,
                automata_ci_execution::discard_execution_output(),
            )
        });
        wait_for_test(
            || cancellation.observations.load(Ordering::SeqCst) > 0,
            "second endpoint operation did not reach its pre-lock cancellation check",
        );
        cancellation.cancel();
        let mutations_before_release = fixture.engine.mutation_count();
        wait_for_test(
            || second_call.is_finished(),
            "queued endpoint did not return within the cancellation bound",
        );
        let queued_error = second_call
            .join()
            .expect("second call thread")
            .expect_err("queued cancellation");
        assert_eq!(queued_error.kind(), ExecutionErrorKind::Cancelled);
        assert_eq!(fixture.engine.mutation_count(), mutations_before_release);

        fixture
            .engine
            .release_guest_exec
            .store(true, Ordering::SeqCst);
        let first_output = first_call
            .join()
            .expect("first call thread")
            .expect("first exec");
        assert_eq!(first_output.termination(), ExecutionTermination::Exited(0));
    });

    assert_eq!(
        fixture
            .engine
            .container(&names.job)
            .expect("running job")
            .state,
        EngineContainerState::Running
    );
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .all(|call| !matches!(call, Call::KillContainer(id) if id == &job.id))
    );
}

#[test]
fn queued_provider_cancellation_returns_before_holder_release_and_mutates_nothing() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("endpoint");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let first_command = ExecutionCommand::new(
        OperationId::from_uuid(Uuid::from_u128(304)),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        spec.workspace().clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(2),
        1024,
    )
    .expect("command");
    fixture
        .engine
        .mutate(|state| state.block_next_guest_exec = true);
    let cancellation = ToggleCancellation::active();

    std::thread::scope(|scope| {
        let first_call = scope.spawn(|| {
            endpoint.exec(
                &first_command,
                &NeverCancelled,
                automata_ci_execution::discard_execution_output(),
            )
        });
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "endpoint operation did not reach the controlled exec",
        );

        let queued_cancellation = cancellation.clone();
        let provider = &fixture.provider;
        let handle = record.handle();
        let provider_call = scope.spawn(move || provider.inspect(handle, &queued_cancellation));
        wait_for_test(
            || cancellation.observations.load(Ordering::SeqCst) > 0,
            "provider operation did not reach cancellation-aware lock acquisition",
        );
        cancellation.cancel();
        let mutations_before_release = fixture.engine.mutation_count();
        wait_for_test(
            || provider_call.is_finished(),
            "queued provider call did not return within the cancellation bound",
        );
        let queued_error = provider_call
            .join()
            .expect("provider call thread")
            .expect_err("queued cancellation");
        assert_eq!(queued_error.kind(), ProviderErrorKind::Cancelled);
        assert_eq!(fixture.engine.mutation_count(), mutations_before_release);

        fixture
            .engine
            .release_guest_exec
            .store(true, Ordering::SeqCst);
        let first_output = first_call
            .join()
            .expect("endpoint call thread")
            .expect("first exec");
        assert_eq!(first_output.termination(), ExecutionTermination::Exited(0));
    });

    assert_eq!(
        fixture
            .engine
            .container(&names.job)
            .expect("running job")
            .state,
        EngineContainerState::Running
    );
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .all(|call| !matches!(call, Call::KillContainer(id) if id == &job.id))
    );
}

#[test]
fn cancellation_dominates_a_simultaneous_guest_transport_failure_and_stops_exact_job() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("endpoint");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let command = ExecutionCommand::new(
        OperationId::from_uuid(Uuid::from_u128(304)),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        spec.workspace().clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(2),
        1024,
    )
    .expect("command");
    fixture
        .engine
        .mutate(|state| state.block_next_guest_exec = true);
    fixture
        .engine
        .fail_released_guest_exec
        .store(true, Ordering::SeqCst);
    let cancellation = ToggleCancellation::active();

    let error = std::thread::scope(|scope| {
        let call = scope.spawn(|| {
            endpoint.exec(
                &command,
                &cancellation,
                automata_ci_execution::discard_execution_output(),
            )
        });
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "guest transport did not reach the controlled failure",
        );
        cancellation.cancel();
        fixture
            .engine
            .release_guest_exec
            .store(true, Ordering::SeqCst);
        call.join()
            .expect("endpoint thread")
            .expect_err("terminal cancellation dominates transport failure")
    });
    assert_eq!(error.kind(), ExecutionErrorKind::Cancelled);
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .any(|call| matches!(call, Call::KillContainer(id) if id == &job.id))
    );
    assert_eq!(
        fixture
            .engine
            .container(&names.job)
            .expect("stopped job")
            .state,
        EngineContainerState::Exited(137)
    );
}

#[test]
fn uncertain_guest_transport_failure_stops_exact_job_and_never_restarts_it() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("endpoint");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let starts_before = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    let command = ExecutionCommand::new(
        OperationId::from_uuid(Uuid::from_u128(305)),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        spec.workspace().clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(2),
        1024,
    )
    .expect("command");
    fixture
        .engine
        .mutate(|state| state.block_next_guest_exec = true);
    fixture
        .engine
        .fail_released_guest_exec
        .store(true, Ordering::SeqCst);

    let error = std::thread::scope(|scope| {
        let call = scope.spawn(|| {
            endpoint.exec(
                &command,
                &NeverCancelled,
                automata_ci_execution::discard_execution_output(),
            )
        });
        wait_for_test(
            || fixture.engine.guest_exec_blocked.load(Ordering::SeqCst),
            "guest transport did not reach the controlled failure",
        );
        fixture
            .engine
            .release_guest_exec
            .store(true, Ordering::SeqCst);
        call.join()
            .expect("endpoint thread")
            .expect_err("uncertain guest transport failure")
    });
    assert_eq!(error.kind(), ExecutionErrorKind::BackendRejected);
    assert_eq!(
        fixture.engine.container(&names.job).expect("job").state,
        EngineContainerState::Exited(137)
    );
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .any(|call| matches!(call, Call::KillContainer(id) if id == &job.id))
    );

    let replay = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("exited job is never restarted");
    assert_eq!(replay.kind(), ProviderErrorKind::InvalidState);
    let starts_after = fixture
        .engine
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::StartContainer(id) if id == &job.id))
        .count();
    assert_eq!(starts_after, starts_before);
}

#[test]
fn cancellation_during_final_custody_reinspection_stops_exact_job() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("endpoint");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let cancellation = ToggleCancellation::active();
    fixture.engine.mutate(|state| {
        state.cancel_after_boundaries = Some((4, Arc::clone(&cancellation.cancelled)));
    });
    let command = ExecutionCommand::new(
        OperationId::from_uuid(Uuid::from_u128(305)),
        ExecutionArgv::new(TargetPath::posix("/bin/true").expect("program"), Vec::new())
            .expect("argv"),
        spec.workspace().clone(),
        ExecutionEnvironment::empty(),
        Duration::from_secs(2),
        1024,
    )
    .expect("command");

    let error = endpoint
        .exec(
            &command,
            &cancellation,
            automata_ci_execution::discard_execution_output(),
        )
        .expect_err("final verification cancellation");
    assert_eq!(error.kind(), ExecutionErrorKind::Cancelled);
    assert!(
        fixture
            .engine
            .calls()
            .iter()
            .any(|call| matches!(call, Call::KillContainer(id) if id == &job.id))
    );
    assert_eq!(
        fixture
            .engine
            .container(&names.job)
            .expect("stopped job")
            .state,
        EngineContainerState::Exited(137)
    );
}

#[test]
fn inherited_image_runtime_defaults_are_rejected_before_mutation() {
    for inherited_default in 0..3 {
        let fixture = Fixture::new();
        fixture.engine.mutate(|state| {
            let image = state
                .images
                .get_mut(job_image().reference())
                .expect("job image");
            match inherited_default {
                0 => image.declared_volumes.push("/data".to_owned()),
                1 => image.declared_exposed_ports.push("8080/tcp".to_owned()),
                2 => image.has_healthcheck = true,
                _ => unreachable!(),
            }
        });
        let error = fixture
            .provider
            .create(&sandbox_spec(), &NeverCancelled)
            .expect_err("image default rejection");
        assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
        assert_eq!(fixture.engine.mutation_count(), 0);
    }

    let fixture = Fixture::new();
    let mut guest = inspected_image(&guest_image(), GUEST_IMAGE_ID);
    guest.has_healthcheck = true;
    assert_eq!(
        verify_image(&fixture.provider.inner.pinned, &guest_image(), &guest),
        Err(LocalDockerErrorCode::ImageMismatch),
        "provider connection uses the same pre-mutation guest-image gate"
    );
}

#[test]
fn daemon_default_ulimit_normalization_fails_closed_and_custody_cleanup_removes_it() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.inject_daemon_default_ulimit_on_next_create = true);
    let spec = sandbox_spec();
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("daemon-normalized ulimit must fail exact inspection");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
    assert_exact_create_recovery(&fixture, &spec, &error);
    let helper = fixture
        .engine
        .container(&names.helper)
        .expect("rejected helper still has recoverable custody");
    assert!(!helper.isolated);

    let request = DestroySandbox::new(
        OperationId::from_uuid(Uuid::from_u128(170)),
        error
            .recovery_handle()
            .expect("post-create failure carries custody handle")
            .clone(),
        spec.generation(),
        spec.custody(),
    );
    assert_eq!(
        fixture
            .provider
            .destroy(&request, &NeverCancelled)
            .expect("custody-only cleanup"),
        DestroyDisposition::Destroyed
    );
    assert!(fixture.engine.container(&names.helper).is_none());
    assert!(fixture.engine.container(&helper.id).is_none());
}

#[test]
fn custody_cleanup_survives_image_loss_runtime_drift_and_invalid_state() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job_id = fixture.engine.container(&names.job).expect("job").id;
    fixture.engine.mutate(|state| {
        state.images.remove(job_image().reference());
        let job = state.containers.get_mut(&names.job).expect("job");
        job.isolated = false;
        job.state = EngineContainerState::Invalid;
        job.definition.memory_bytes = 0;
    });

    let request = DestroySandbox::new(
        OperationId::from_uuid(Uuid::from_u128(171)),
        record.handle().clone(),
        record.generation(),
        spec.custody(),
    );
    assert_eq!(
        fixture
            .provider
            .destroy(&request, &NeverCancelled)
            .expect("custody does not depend on executable state or live image"),
        DestroyDisposition::Destroyed
    );
    assert!(fixture.engine.container(&names.job).is_none());
    assert!(fixture.engine.container(&job_id).is_none());
}

#[test]
fn custody_cleanup_survives_missing_or_drifted_imported_proxy_image() {
    for missing in [true, false] {
        let fixture = Fixture::new();
        let spec = sandbox_spec();
        let record = fixture
            .provider
            .create(&spec, &NeverCancelled)
            .expect("create");
        let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
        let job_id = fixture.engine.container(&names.job).expect("job").id;
        let proxy_id = fixture
            .engine
            .container(&names.results_proxy)
            .expect("Results proxy")
            .id;
        fixture.engine.mutate(|state| {
            if missing {
                state.images.remove(proxy_image().reference());
            } else {
                state
                    .images
                    .get_mut(proxy_image().reference())
                    .expect("Results proxy image")
                    .repo_digests = vec![proxy_manifest_digest_reference()];
            }
        });

        let request = DestroySandbox::new(
            OperationId::from_uuid(Uuid::from_u128(0x171)),
            record.handle().clone(),
            record.generation(),
            spec.custody(),
        );
        assert_eq!(
            fixture
                .provider
                .destroy(&request, &NeverCancelled)
                .expect("custody-only cleanup must not depend on the imported image"),
            DestroyDisposition::Destroyed
        );
        assert!(fixture.engine.container(&names.job).is_none());
        assert!(fixture.engine.container(&job_id).is_none());
        assert!(fixture.engine.container(&names.results_proxy).is_none());
        assert!(fixture.engine.container(&proxy_id).is_none());
        assert!(
            !fixture
                .engine
                .state
                .lock()
                .expect("fake state")
                .networks
                .contains_key(&names.results_front)
        );
        let image = fixture
            .engine
            .state
            .lock()
            .expect("fake state")
            .images
            .get(proxy_image().reference())
            .cloned();
        if missing {
            assert!(
                image.is_none(),
                "destroy must not recreate the imported image"
            );
        } else {
            assert_eq!(
                image.expect("drifted image remains untouched").repo_digests,
                [proxy_manifest_digest_reference()]
            );
        }
    }
}

#[test]
fn custody_cleanup_rejects_noncanonical_or_extra_managed_labels_before_mutation() {
    for tamper in 0..3 {
        let fixture = Fixture::new();
        let spec = sandbox_spec();
        let record = fixture
            .provider
            .create(&spec, &NeverCancelled)
            .expect("create");
        let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
        fixture.engine.mutate(|state| {
            let labels = &mut state
                .containers
                .get_mut(&names.job)
                .expect("job")
                .definition
                .labels;
            match tamper {
                0 => {
                    labels.remove(LABEL_SPEC_DIGEST);
                }
                1 => {
                    labels.insert(LABEL_SPEC_DIGEST.to_owned(), "not-a-digest".to_owned());
                }
                2 => {
                    labels.insert("io.automata.local.unreviewed".to_owned(), "true".to_owned());
                }
                _ => unreachable!(),
            }
        });
        let mutations = fixture.engine.mutation_count();
        let request = DestroySandbox::new(
            OperationId::from_uuid(Uuid::from_u128(172)),
            record.handle().clone(),
            record.generation(),
            spec.custody(),
        );
        let error = fixture
            .provider
            .destroy(&request, &NeverCancelled)
            .expect_err("invalid custody labels cannot authorize deletion");
        assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
        assert_eq!(fixture.engine.mutation_count(), mutations);
        assert!(fixture.engine.container(&names.job).is_some());
    }
}

#[test]
fn cleanup_proves_both_the_deterministic_name_and_original_id_absent() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job_id = fixture.engine.container(&names.job).expect("job").id;
    fixture
        .engine
        .mutate(|state| state.rename_removed_container_instead = true);
    let request = DestroySandbox::new(
        OperationId::from_uuid(Uuid::from_u128(173)),
        record.handle().clone(),
        record.generation(),
        spec.custody(),
    );
    let error = fixture
        .provider
        .destroy(&request, &NeverCancelled)
        .expect_err("name absence alone cannot prove deletion");
    assert_eq!(error.kind(), ProviderErrorKind::AdapterUnavailable);
    assert!(fixture.engine.container(&names.job).is_none());
    assert!(
        fixture
            .engine
            .state
            .lock()
            .expect("state")
            .containers
            .values()
            .any(|container| container.id == job_id)
    );
}

#[test]
fn foreign_name_collision_fails_closed_without_mutation() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    fixture.engine.mutate(|state| {
        let id = state.object_id();
        state.containers.insert(
            names.job.clone(),
            InspectedContainer {
                id,
                image_id: JOB_IMAGE_ID.to_owned(),
                definition: ContainerDefinition {
                    name: names.job,
                    image: job_image().reference().to_owned(),
                    entrypoint: "/bin/false".to_owned(),
                    arguments: Vec::new(),
                    labels: BTreeMap::new(),
                    environment: Vec::new(),
                    tmpfs: BTreeMap::new(),
                    working_directory: "/".to_owned(),
                    user: "0:0".to_owned(),
                    read_only_root: false,
                    memory_bytes: 1,
                    nano_cpus: 1,
                    pids_limit: 1,
                    primary_network: None,
                    networks: BTreeMap::new(),
                    capture_logs: false,
                },
                state: EngineContainerState::Created,
                isolated: false,
            },
        );
    });
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("foreign collision");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(fixture.engine.mutation_count(), 0);
}

#[test]
fn long_valid_workspace_fails_before_front_network_mutation() {
    let fixture = Fixture::new();
    let long_workspace = TargetPath::posix(format!("/workspace/{}", "a".repeat(128)))
        .expect("long workspace remains a valid target path");
    let spec = sandbox_spec_with_workspace(long_workspace);
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("workspace outside the deterministic tar layout ceiling");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
    assert_eq!(error.outcome(), OperationOutcome::KnownNoEffect);
    assert!(error.recovery_handle().is_none());
    assert_eq!(fixture.engine.mutation_count(), 0);
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    assert!(
        !fixture
            .engine
            .state
            .lock()
            .expect("state")
            .networks
            .contains_key(&names.results_front)
    );
}

#[test]
fn merged_label_overflow_fails_before_front_network_mutation() {
    let fixture = Fixture::new();
    fixture.engine.mutate(|state| {
        let labels = &mut state
            .images
            .get_mut(job_image().reference())
            .expect("job image")
            .labels;
        for index in 0..MAX_RESOURCE_LABELS {
            labels.insert(format!("example.test.label-{index}"), "value".to_owned());
        }
    });
    let spec = sandbox_spec();
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("merged job labels exceed the exact Engine ceiling");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
    assert_eq!(error.outcome(), OperationOutcome::KnownNoEffect);
    assert!(error.recovery_handle().is_none());
    assert_eq!(fixture.engine.mutation_count(), 0);
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    assert!(
        !fixture
            .engine
            .state
            .lock()
            .expect("state")
            .networks
            .contains_key(&names.results_front)
    );
}

#[test]
fn cancellation_at_post_front_prepare_job_and_proxy_boundaries_is_recoverable() {
    for boundary in [3, 6, 8] {
        let fixture = Fixture::new();
        let spec = sandbox_spec();
        let cancellation = ToggleCancellation::active();
        fixture.engine.mutate(|state| {
            state.cancel_after_boundaries = Some((boundary, Arc::clone(&cancellation.cancelled)));
        });

        let error = fixture
            .provider
            .create(&spec, &cancellation)
            .expect_err("post-front boundary cancellation");

        assert_eq!(error.kind(), ProviderErrorKind::Cancelled);
        let calls = fixture.engine.calls();
        let created = calls
            .iter()
            .filter_map(|call| match call {
                Call::CreateContainer(definition) => Some(definition.name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        match boundary {
            3 => assert!(
                created.is_empty(),
                "prepare boundary must precede helper mutation"
            ),
            6 => assert!(
                created.iter().all(|name| name.ends_with("-guest-source")),
                "job boundary must precede job mutation"
            ),
            8 => {
                assert!(created.iter().any(|name| name.ends_with("-job")));
                assert!(
                    created.iter().all(|name| !name.ends_with("-results-proxy")),
                    "proxy boundary must precede proxy mutation"
                );
            }
            _ => unreachable!(),
        }
        destroy_create_recovery(&fixture, &spec, &error);
    }
}

#[test]
fn adversarial_guest_source_archive_fails_before_job_creation() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    fixture
        .engine
        .mutate(|state| state.invalid_guest_source_archive = true);
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("multi-entry guest source archive");
    assert_eq!(error.kind(), ProviderErrorKind::BackendRejected);
    assert!(!fixture.engine.calls().iter().any(|call| {
        matches!(call, Call::CreateContainer(definition) if definition.name.ends_with("-job"))
    }));
    destroy_create_recovery(&fixture, &spec, &error);
}

#[test]
fn helper_rename_instead_of_removal_is_detected_by_exact_id() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.rename_instead_of_next_remove = true);
    let error = fixture
        .provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect_err("renamed exact helper must not count as removed");
    assert_eq!(error.kind(), ProviderErrorKind::AdapterUnavailable);

    let state = fixture.engine.state.lock().expect("fake state");
    let retained = state
        .containers
        .values()
        .find(|container| container.definition.name.ends_with("-guest-source-renamed"))
        .expect("renamed exact helper remains present");
    let removed_id = state
        .calls
        .iter()
        .find_map(|call| match call {
            Call::RemoveContainer(id) => Some(id),
            _ => None,
        })
        .expect("attempted exact helper removal");
    assert_eq!(&retained.id, removed_id);
    assert!(
        !state.containers.contains_key(
            retained
                .definition
                .name
                .strip_suffix("-renamed")
                .expect("renamed suffix")
        )
    );
}

#[test]
fn name_replacement_after_archive_upload_is_never_adopted_or_started() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.replace_after_upload = true);
    let spec = sandbox_spec();
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("post-upload name replacement");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
    assert_exact_create_recovery(&fixture, &spec, &error);
    let replacement = fixture.engine.container(&names.job).expect("replacement");
    let calls = fixture.engine.calls();
    let uploaded_id = calls
        .iter()
        .find_map(|call| match call {
            Call::UploadArchive(id) => Some(id),
            _ => None,
        })
        .expect("upload call");
    assert_ne!(&replacement.id, uploaded_id);
    assert!(
        !calls
            .iter()
            .any(|call| matches!(call, Call::StartContainer(_)))
    );
}

#[test]
fn name_replacement_after_start_is_never_adopted_or_bootstrapped() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.replace_after_start = true);
    let spec = sandbox_spec();
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("post-start name replacement");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
    assert_exact_create_recovery(&fixture, &spec, &error);
    let replacement = fixture.engine.container(&names.job).expect("replacement");
    let calls = fixture.engine.calls();
    let started_id = calls
        .iter()
        .find_map(|call| match call {
            Call::StartContainer(id) => Some(id),
            _ => None,
        })
        .expect("start call");
    assert_ne!(&replacement.id, started_id);
    assert!(
        !calls
            .iter()
            .any(|call| matches!(call, Call::CreateExec(_, _)))
    );
}

#[test]
fn delayed_results_proxy_readiness_is_polled_to_one_exact_line() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.results_readiness_empty_reads = 2);
    fixture
        .provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect("bounded delayed readiness");
    assert_eq!(
        fixture
            .engine
            .state
            .lock()
            .expect("state")
            .results_log_reads,
        3
    );
}

#[test]
fn nonempty_nonexact_results_proxy_readiness_is_rejected_immediately() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    fixture.engine.mutate(|state| {
        state.results_readiness_bytes = Some(b"{\"version\":1}\n".to_vec());
    });
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("nonexact readiness must fail");
    assert_eq!(error.kind(), ProviderErrorKind::BackendRejected);
    assert_eq!(
        fixture
            .engine
            .state
            .lock()
            .expect("state")
            .results_log_reads,
        1
    );
    destroy_create_recovery(&fixture, &spec, &error);
}

#[test]
fn results_proxy_replacement_during_readiness_poll_is_detected() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    fixture.engine.mutate(|state| {
        state.results_readiness_empty_reads = 1;
        state.replace_proxy_after_empty_readiness = true;
    });
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("replacement during readiness must fail");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
    assert_exact_create_recovery(&fixture, &spec, &error);
}

#[test]
fn cancellation_interrupts_results_proxy_readiness_poll() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    fixture
        .engine
        .mutate(|state| state.results_readiness_empty_reads = usize::MAX);
    let cancellation = ToggleCancellation::active();
    let error = std::thread::scope(|scope| {
        let call = scope.spawn(|| fixture.provider.create(&spec, &cancellation));
        wait_for_test(
            || {
                fixture
                    .engine
                    .state
                    .lock()
                    .expect("state")
                    .results_log_reads
                    > 0
            },
            "readiness polling did not begin",
        );
        cancellation.cancel();
        wait_for_test(
            || call.is_finished(),
            "cancelled readiness poll did not return within the test bound",
        );
        call.join()
            .expect("create thread")
            .expect_err("cancelled readiness")
    });
    assert_eq!(error.kind(), ProviderErrorKind::Cancelled);
    destroy_create_recovery(&fixture, &spec, &error);
}

#[test]
fn readiness_preserves_transit_and_target_engine_failure_categories() {
    for target_failure in [false, true] {
        for (engine_error, expected_kind) in engine_failure_categories() {
            let fixture = Fixture::new();
            let record = fixture
                .provider
                .create(&sandbox_spec(), &NeverCancelled)
                .expect("create Results topology");
            let mutations = fixture.engine.mutation_count();
            fixture.engine.mutate(|state| {
                if target_failure {
                    state.readiness_followup_target_error = Some(engine_error);
                } else {
                    state.readiness_followup_transit_inspect_error = Some(engine_error);
                }
            });

            let error = fixture
                .provider
                .inspect(record.handle(), &NeverCancelled)
                .expect_err("injected readiness Engine failure");

            assert_eq!(error.kind(), expected_kind);
            assert_ne!(error.kind(), ProviderErrorKind::OwnershipMismatch);
            assert_eq!(fixture.engine.mutation_count(), mutations);
            assert_eq!(
                fixture
                    .provider
                    .inspect(record.handle(), &NeverCancelled)
                    .expect("transient readiness failure must retain custody")
                    .state(),
                SandboxState::Running
            );
        }
    }
}

#[test]
fn name_replacement_after_fresh_readiness_probe_is_not_reported_running() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.replace_after_probe = true);
    let error = fixture
        .provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect_err("post-readiness replacement");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
}

#[test]
fn name_replacement_after_recovery_probe_is_not_adopted() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("initial create");
    fixture
        .engine
        .mutate(|state| state.replace_after_probe = true);
    let error = fixture
        .reopen_provider()
        .create(&spec, &NeverCancelled)
        .expect_err("post-recovery-probe replacement");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
}

#[test]
fn name_replacement_after_attach_probe_is_not_attached() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    fixture
        .engine
        .mutate(|state| state.replace_after_probe = true);
    let error = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect_err("post-attach-probe replacement");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
}

#[test]
fn name_replacement_during_final_inspect_boundary_is_not_reported() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    fixture
        .engine
        .mutate(|state| state.replace_job_after_boundaries = Some(2));
    let error = fixture
        .provider
        .inspect(record.handle(), &NeverCancelled)
        .expect_err("final-boundary replacement must invalidate the snapshot");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
}

#[test]
fn destroy_rejects_a_helper_recreated_while_the_job_is_removed() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    let mut base_labels = job.definition.labels;
    base_labels.remove(LABEL_RESOURCE_KIND);
    let definition = helper_definition(
        &names,
        guest_image().reference(),
        &BTreeMap::new(),
        &[],
        &base_labels,
    );
    let original_helper_id = fixture.engine.state.lock().expect("state").object_id();
    fixture.engine.mutate(|state| {
        state.containers.insert(
            names.helper.clone(),
            InspectedContainer {
                id: original_helper_id.clone(),
                image_id: GUEST_IMAGE_ID.to_owned(),
                definition,
                state: EngineContainerState::Created,
                isolated: true,
            },
        );
        state.recreate_first_removed_after_following_remove = true;
    });
    let request = DestroySandbox::new(
        OperationId::from_uuid(Uuid::from_u128(200)),
        record.handle().clone(),
        record.generation(),
        spec.custody(),
    );
    let error = fixture
        .provider
        .destroy(&request, &NeverCancelled)
        .expect_err("recreated deterministic helper name must prevent success");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
    assert!(fixture.engine.container(&names.job).is_none());
    let recreated = fixture
        .engine
        .container(&names.helper)
        .expect("recreated helper remains foreign to cleanup success");
    assert_ne!(recreated.id, original_helper_id);
}

#[test]
fn destroy_rejects_a_job_renamed_instead_of_exact_id_removal() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    fixture
        .engine
        .mutate(|state| state.rename_instead_of_next_remove = true);
    let request = DestroySandbox::new(
        OperationId::from_uuid(Uuid::from_u128(201)),
        record.handle().clone(),
        record.generation(),
        spec.custody(),
    );

    let error = fixture
        .provider
        .destroy(&request, &NeverCancelled)
        .expect_err("renamed exact job ID must prevent removal success");

    assert_eq!(error.kind(), ProviderErrorKind::AdapterUnavailable);
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    assert!(fixture.engine.container(&names.job).is_none());
    assert!(
        fixture
            .engine
            .state
            .lock()
            .expect("state")
            .containers
            .values()
            .any(|container| {
                container.definition.name == format!("{}-renamed", names.job)
                    && container.state == EngineContainerState::Exited(137)
            })
    );
}

#[test]
fn exact_realized_configuration_is_rechecked_on_attach() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    fixture.engine.mutate(|state| {
        state.containers.get_mut(&names.job).expect("job").isolated = false;
    });
    let error = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect_err("tampered isolation");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
}

#[test]
fn provider_advertises_only_its_current_network_contract() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .provider
            .capabilities()
            .supports(SandboxCapability::PrivateEgress)
    );
    assert!(
        !fixture
            .provider
            .capabilities()
            .supports(SandboxCapability::NetworkDisabled)
    );
}

#[test]
fn results_transport_rejects_generic_or_public_targets() {
    for (network_id, container_id, address) in [
        ("short", RESULTS_CONTAINER_ID, Ipv4Addr::new(10, 91, 0, 2)),
        (TRANSIT_NETWORK_ID, "short", Ipv4Addr::new(10, 91, 0, 2)),
        (
            TRANSIT_NETWORK_ID,
            RESULTS_CONTAINER_ID,
            Ipv4Addr::new(203, 0, 113, 2),
        ),
    ] {
        assert_eq!(
            LocalDockerResultsTransport::new(
                proxy_image(),
                results_plan_digest(),
                network_id,
                container_id,
                address,
            )
            .expect_err("invalid closed transport")
            .code(),
            LocalDockerErrorCode::ResultsTransportMismatch
        );
    }
}

#[test]
fn imported_results_proxy_accepts_only_the_two_coupled_engine_representations() {
    let fixture = Fixture::new();
    let image = proxy_image();
    let mut classic = inspected_imported_image(&image, PROXY_CONFIG_IMAGE_ID, vec![]);
    qualify_results_proxy_image(&mut classic);
    assert!(verify_results_proxy_image(&fixture.provider.inner.pinned, &image, &classic).is_ok());

    let mut containerd = inspected_imported_image(
        &image,
        PROXY_MANIFEST_IMAGE_ID,
        vec![proxy_manifest_digest_reference()],
    );
    qualify_results_proxy_image(&mut containerd);
    assert!(
        verify_results_proxy_image(&fixture.provider.inner.pinned, &image, &containerd).is_ok()
    );

    let mut invalid = Vec::new();
    let mut config_with_digest = classic.clone();
    config_with_digest.repo_digests = vec![proxy_manifest_digest_reference()];
    invalid.push(config_with_digest);
    let mut manifest_without_digest = containerd.clone();
    manifest_without_digest.repo_digests.clear();
    invalid.push(manifest_without_digest);
    let mut unknown_id = classic.clone();
    unknown_id.id = format!("sha256:{}", "7a".repeat(32));
    invalid.push(unknown_id);
    let mut wrong_tag = classic.clone();
    wrong_tag.repo_tags = vec!["automata.local/foreign:latest".to_owned()];
    invalid.push(wrong_tag);
    let mut extra_tag = classic.clone();
    extra_tag
        .repo_tags
        .push("automata.local/foreign:latest".to_owned());
    invalid.push(extra_tag);
    let mut wrong_digest = containerd.clone();
    wrong_digest.repo_digests = vec![format!("automata.local/foreign@{PROXY_MANIFEST_IMAGE_ID}")];
    invalid.push(wrong_digest);
    let mut extra_digest = containerd;
    extra_digest
        .repo_digests
        .push(format!("automata.local/foreign@{PROXY_MANIFEST_IMAGE_ID}"));
    invalid.push(extra_digest);

    for inspected in invalid {
        assert_eq!(
            verify_results_proxy_image(&fixture.provider.inner.pinned, &image, &inspected),
            Err(LocalDockerErrorCode::ImageMismatch)
        );
    }
}

#[test]
fn imported_proxy_representation_drift_is_rejected_before_operation_mutation() {
    let fixture = Fixture::new();
    fixture.engine.mutate(|state| {
        state
            .images
            .get_mut(proxy_image().reference())
            .expect("Results proxy image")
            .repo_digests = vec![proxy_manifest_digest_reference()];
    });
    let mutations = fixture.engine.mutation_count();

    let error = fixture
        .provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect_err("a config ID paired with a RepoDigest must fail closed");

    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(fixture.engine.mutation_count(), mutations);
}

#[test]
fn attach_and_inspect_reattest_missing_or_drifted_imported_proxy_before_mutation() {
    for boundary in ["attach", "inspect"] {
        for missing in [true, false] {
            let fixture = Fixture::new();
            let spec = sandbox_spec();
            let record = fixture
                .provider
                .create(&spec, &NeverCancelled)
                .expect("create before image drift");
            fixture.engine.mutate(|state| {
                if missing {
                    state.images.remove(proxy_image().reference());
                } else {
                    state
                        .images
                        .get_mut(proxy_image().reference())
                        .expect("Results proxy image")
                        .repo_digests = vec![proxy_manifest_digest_reference()];
                }
            });
            let mutations = fixture.engine.mutation_count();

            let error = match boundary {
                "attach" => fixture
                    .provider
                    .attach(record.handle(), &NeverCancelled)
                    .expect_err("attach must reattest the imported image"),
                "inspect" => fixture
                    .provider
                    .inspect(record.handle(), &NeverCancelled)
                    .expect_err("inspect must reattest the imported image"),
                _ => unreachable!(),
            };
            assert_eq!(
                error.kind(),
                if missing {
                    ProviderErrorKind::NotFound
                } else {
                    ProviderErrorKind::OwnershipMismatch
                },
                "unexpected {boundary} result for missing={missing}"
            );
            assert_eq!(fixture.engine.mutation_count(), mutations);
        }
    }
}

#[test]
fn endpoint_exchange_reattests_missing_or_drifted_imported_proxy_before_exec_mutation() {
    for missing in [true, false] {
        let fixture = Fixture::new();
        let spec = sandbox_spec();
        let record = fixture
            .provider
            .create(&spec, &NeverCancelled)
            .expect("create before image drift");
        let endpoint = fixture
            .provider
            .attach(record.handle(), &NeverCancelled)
            .expect("attach before image drift");
        fixture.engine.mutate(|state| {
            if missing {
                state.images.remove(proxy_image().reference());
            } else {
                state
                    .images
                    .get_mut(proxy_image().reference())
                    .expect("Results proxy image")
                    .repo_digests = vec![proxy_manifest_digest_reference()];
            }
        });
        let mutations = fixture.engine.mutation_count();

        let error = endpoint
            .exec(
                &true_command(&spec, 0x172),
                &NeverCancelled,
                automata_ci_execution::discard_execution_output(),
            )
            .expect_err("endpoint exchange must reattest the imported image");
        assert_eq!(
            error.kind(),
            if missing {
                ExecutionErrorKind::NotFound
            } else {
                ExecutionErrorKind::OwnershipMismatch
            }
        );
        assert_eq!(
            fixture.engine.mutation_count(),
            mutations,
            "no guest exec may be created after imported-image reattestation fails"
        );
    }
}

#[test]
fn sandbox_fingerprint_binds_proxy_config_manifest_tag_and_desired_plan() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let base = verified_results_transport(&fixture.installation);
    let base_fingerprint = spec_fingerprint(&spec, &fixture.installation, &guest_image(), &base)
        .expect("base fingerprint");

    let mut config_changed = base.clone();
    config_changed.requested.proxy_image = LocalImportedImage::new(
        format!("sha256:{}", "7a".repeat(32)),
        PROXY_MANIFEST_IMAGE_ID,
    )
    .expect("changed config identity");
    assert_eq!(
        config_changed.requested.proxy_image.reference(),
        base.requested.proxy_image.reference(),
        "the config-ID variant deliberately holds the derived tag constant"
    );

    let mut manifest_and_tag_changed = base.clone();
    manifest_and_tag_changed.requested.proxy_image =
        LocalImportedImage::new(PROXY_CONFIG_IMAGE_ID, format!("sha256:{}", "7b".repeat(32)))
            .expect("changed manifest identity");
    assert_ne!(
        manifest_and_tag_changed.requested.proxy_image.reference(),
        base.requested.proxy_image.reference(),
        "the closed local tag is derived from the manifest identity"
    );

    let mut plan_changed = base.clone();
    plan_changed.requested.plan_digest = Sha256Digest::from_bytes([0x78; 32]);

    let variants = [config_changed, manifest_and_tag_changed, plan_changed].map(|results| {
        spec_fingerprint(&spec, &fixture.installation, &guest_image(), &results)
            .expect("variant fingerprint")
    });
    assert!(
        variants
            .iter()
            .all(|fingerprint| fingerprint != &base_fingerprint)
    );
    assert_eq!(variants.into_iter().collect::<BTreeSet<_>>().len(), 3);
}

#[test]
fn desired_plan_label_drift_is_rejected_before_operation_mutation() {
    for (key, replacement) in [
        (LABEL_PLAN_DIGEST, None),
        (LABEL_PLAN_DIGEST, Some("00".repeat(32))),
        (LABEL_RESULTS_TRANSPORT_SCHEMA, Some("1".to_owned())),
    ] {
        let fixture = Fixture::new();
        fixture.engine.mutate(|state| {
            let labels = &mut state
                .networks
                .get_mut(&results_transit_name(&fixture.installation))
                .expect("Results transit")
                .labels;
            if let Some(replacement) = replacement.clone() {
                labels.insert(key.to_owned(), replacement);
            } else {
                labels.remove(key);
            }
        });
        let mutations = fixture.engine.mutation_count();

        let error = fixture
            .provider
            .create(&sandbox_spec(), &NeverCancelled)
            .expect_err("the shared transit must carry the exact desired plan digest");

        assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
        assert_eq!(fixture.engine.mutation_count(), mutations);
    }
}

#[test]
fn stale_results_proxy_image_protocol_is_rejected_before_mutation() {
    let fixture = Fixture::new();
    fixture.engine.mutate(|state| {
        state
            .images
            .get_mut(proxy_image().reference())
            .expect("Results proxy image")
            .labels
            .insert(
                RESULTS_PROXY_IMAGE_PROTOCOL_LABEL.to_owned(),
                "1".to_owned(),
            );
    });
    let mut results = verified_results_transport(&fixture.installation);
    results.proxy_image_labels.insert(
        RESULTS_PROXY_IMAGE_PROTOCOL_LABEL.to_owned(),
        "1".to_owned(),
    );
    let provider = LocalDockerProvider::with_test_engine(
        PinnedDockerEngine::for_test(EngineArchitecture::Amd64, fixture.engine.clone()),
        fixture.engine.clone(),
        fixture.installation.clone(),
        guest_image(),
        GUEST_IMAGE_ID.to_owned(),
        results,
        RunnerId::from_uuid(Uuid::from_u128(2)),
    );
    let mutations = fixture.engine.mutation_count();

    let error = provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect_err("the pre-Results image protocol must fail closed");

    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(fixture.engine.mutation_count(), mutations);
}

#[test]
fn deterministic_results_addresses_cover_every_current_runner_custody() {
    let fixture = Fixture::new();
    let runner_id = RunnerId::from_uuid(Uuid::from_u128(2));
    let transport = verified_results_transport(&fixture.installation);
    let pool = results_front_pool(&fixture.installation);
    let mut front_networks = BTreeSet::new();
    let mut transit_addresses = BTreeSet::new();
    let custodies = std::iter::once(SandboxCustody::ProfileAdmission { runner_id }).chain(
        (1..=crate::MAXIMUM_LOCAL_DOCKER_JOB_SLOTS).map(|slot| SandboxCustody::Job {
            runner_id,
            slot_ordinal: NonZeroU16::new(slot).expect("nonzero slot"),
        }),
    );

    for custody in custodies {
        let front = results_front_network(&fixture.installation, custody).expect("front subnet");
        assert_eq!(front.prefix, RESULTS_FRONT_NETWORK_PREFIX);
        assert!(pool.contains(front.network));
        assert!(pool.contains(front.broadcast()));
        assert!(front_networks.insert(front.network));
        assert_eq!(
            network_host_address(&front, 1).expect("front gateway"),
            Ipv4Addr::from(u32::from(front.network) + 1)
        );
        assert_eq!(
            network_host_address(&front, 2).expect("proxy address"),
            Ipv4Addr::from(u32::from(front.network) + 2)
        );
        assert_eq!(
            network_host_address(&front, 3).expect("job address"),
            Ipv4Addr::from(u32::from(front.network) + 3)
        );

        let transit = transit_proxy_address(
            &transport.transit_network,
            transport.transit_gateway,
            transport.requested.results_address,
            custody,
        )
        .expect("transit proxy address");
        assert!(transport.transit_network.usable(transit));
        assert_ne!(transit, transport.transit_gateway);
        assert_ne!(transit, transport.requested.results_address);
        assert!(transit_addresses.insert(transit));
    }

    assert_eq!(front_networks.len(), 257);
    assert_eq!(transit_addresses.len(), 257);
}

#[test]
fn minimum_transit_prefix_has_capacity_for_every_target_hole_position() {
    let transit = Ipv4Network {
        network: Ipv4Addr::new(10, 91, 0, 0),
        prefix: 23,
    };
    let gateway = network_host_address(&transit, 1).expect("gateway");
    let runner_id = RunnerId::from_uuid(Uuid::from_u128(2));
    for target_offset in [2, 250, 510] {
        let target = network_host_address(&transit, target_offset).expect("target");
        let addresses = std::iter::once(SandboxCustody::ProfileAdmission { runner_id })
            .chain(
                (1..=crate::MAXIMUM_LOCAL_DOCKER_JOB_SLOTS).map(|slot| SandboxCustody::Job {
                    runner_id,
                    slot_ordinal: NonZeroU16::new(slot).expect("slot"),
                }),
            )
            .map(|custody| {
                transit_proxy_address(&transit, gateway, target, custody)
                    .expect("minimum transit capacity")
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(addresses.len(), 257);
        assert!(!addresses.contains(&gateway));
        assert!(!addresses.contains(&target));
        assert!(addresses.iter().all(|address| transit.usable(*address)));
    }
}

#[test]
fn default_installation_front_address_plan_is_a_stable_golden_vector() {
    let installation = Installation::verified(
        InstallationName::default(),
        InstallationId::from_str("00000000-0000-4000-8000-000000000001").expect("installation ID"),
    );
    let runner_id = RunnerId::from_uuid(Uuid::from_u128(2));
    assert_eq!(
        results_front_pool(&installation),
        Ipv4Network {
            network: Ipv4Addr::new(10, 223, 0, 0),
            prefix: 20,
        }
    );
    for (custody, expected) in [
        (
            SandboxCustody::ProfileAdmission { runner_id },
            Ipv4Addr::new(10, 223, 0, 0),
        ),
        (
            SandboxCustody::Job {
                runner_id,
                slot_ordinal: NonZeroU16::new(1).expect("slot"),
            },
            Ipv4Addr::new(10, 223, 0, 8),
        ),
        (
            SandboxCustody::Job {
                runner_id,
                slot_ordinal: NonZeroU16::new(256).expect("slot"),
            },
            Ipv4Addr::new(10, 223, 8, 0),
        ),
    ] {
        assert_eq!(
            results_front_network(&installation, custody)
                .expect("front network")
                .network,
            expected
        );
    }
}

#[test]
fn one_runner_three_worker_slots_realize_disjoint_closed_topologies() {
    let fixture = Fixture::new();
    let resources = ResourceLimits::new(256 * 1024 * 1024, 2_000, 128).expect("limits");
    let specs = (1_u16..=3)
        .map(|slot| {
            sandbox_spec_with_identity_and_resources(
                100 + u128::from(slot),
                7,
                SandboxCustody::Job {
                    runner_id: RunnerId::from_uuid(Uuid::from_u128(2)),
                    slot_ordinal: NonZeroU16::new(slot).expect("slot"),
                },
                resources,
            )
        })
        .collect::<Vec<_>>();
    let records = specs
        .iter()
        .map(|spec| {
            fixture
                .provider
                .create(spec, &NeverCancelled)
                .expect("three-worker topology")
        })
        .collect::<Vec<_>>();

    let state = fixture.engine.state.lock().expect("state");
    let transit = state
        .networks
        .values()
        .find(|network| network.id == TRANSIT_NETWORK_ID)
        .expect("transit");
    assert_eq!(transit.containers.len(), 4);
    let mut proxy_transit_addresses = BTreeSet::new();
    let mut front_networks = BTreeSet::new();
    for spec in &specs {
        let names = ResourceNames::for_spec(&fixture.installation, spec).expect("names");
        let front = state
            .networks
            .get(&names.results_front)
            .expect("slot front network");
        assert_eq!(
            front.ipv4_network,
            results_front_network(&fixture.installation, spec.custody()).expect("front mapping")
        );
        assert!(front_networks.insert(front.ipv4_network.network));
        let proxy = state
            .containers
            .get(&names.results_proxy)
            .expect("slot proxy");
        let transit_attachment = proxy
            .definition
            .networks
            .get(&transit.name)
            .expect("proxy transit attachment");
        assert_eq!(
            transit_attachment.ipv4_address,
            transit_proxy_address(
                &transit.ipv4_network,
                transit.ipv4_gateway,
                Ipv4Addr::new(10, 91, 0, 2),
                spec.custody(),
            )
            .expect("transit mapping")
        );
        assert!(proxy_transit_addresses.insert(transit_attachment.ipv4_address));
    }
    drop(state);
    assert_eq!(front_networks.len(), 3);
    assert_eq!(proxy_transit_addresses.len(), 3);

    for (record, spec) in records.into_iter().zip(specs).rev() {
        let destroy = DestroySandbox::new(
            OperationId::from_uuid(Uuid::new_v4()),
            record.handle().clone(),
            record.generation(),
            spec.custody(),
        );
        assert_eq!(
            fixture
                .provider
                .destroy(&destroy, &NeverCancelled)
                .expect("destroy worker topology"),
            DestroyDisposition::Destroyed
        );
    }
    let state = fixture.engine.state.lock().expect("state");
    assert_eq!(state.networks.len(), 1);
    assert_eq!(
        state
            .networks
            .values()
            .next()
            .expect("shared transit")
            .containers
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        [RESULTS_CONTAINER_ID.to_owned()]
    );
}

#[test]
fn distinct_worker_slots_create_concurrently_without_transit_allocation_races() {
    let fixture = Fixture::new();
    let resources = ResourceLimits::new(256 * 1024 * 1024, 2_000, 128).expect("limits");
    let specs = (1_u16..=3)
        .map(|slot| {
            sandbox_spec_with_identity_and_resources(
                200 + u128::from(slot),
                7,
                SandboxCustody::Job {
                    runner_id: RunnerId::from_uuid(Uuid::from_u128(2)),
                    slot_ordinal: NonZeroU16::new(slot).expect("slot"),
                },
                resources,
            )
        })
        .collect::<Vec<_>>();
    std::thread::scope(|scope| {
        let calls = specs
            .iter()
            .map(|spec| {
                scope.spawn(|| {
                    fixture
                        .provider
                        .create(spec, &NeverCancelled)
                        .expect("concurrent slot creation")
                })
            })
            .collect::<Vec<_>>();
        for call in calls {
            assert_eq!(
                call.join().expect("create thread").state(),
                SandboxState::Running
            );
        }
    });

    let state = fixture.engine.state.lock().expect("state");
    let transit = state
        .networks
        .values()
        .find(|network| network.id == TRANSIT_NETWORK_ID)
        .expect("transit");
    assert_eq!(transit.containers.len(), 4);
    assert_eq!(
        transit
            .containers
            .values()
            .map(|endpoint| endpoint.ipv4_address)
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
}

#[test]
fn cancellation_interrupts_shared_transit_peer_attestation() {
    let fixture = Fixture::new();
    let record = fixture
        .provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect("create peer for cancellation test");
    fixture
        .engine
        .peer_inspection_delay_millis
        .store(5_000, Ordering::SeqCst);
    let cancellation = ToggleCancellation::active();

    let error = std::thread::scope(|scope| {
        let call = scope.spawn(|| fixture.provider.inspect(record.handle(), &cancellation));
        wait_for_test(
            || {
                fixture
                    .engine
                    .maximum_peer_inspections_in_flight
                    .load(Ordering::SeqCst)
                    > 0
            },
            "shared-transit peer attestation did not begin",
        );
        cancellation.cancel();
        wait_for_test(
            || call.is_finished(),
            "cancelled shared-transit attestation did not return within the test bound",
        );
        call.join()
            .expect("inspect thread")
            .expect_err("cancelled peer attestation")
    });

    assert_eq!(error.kind(), ProviderErrorKind::Cancelled);
}

#[test]
fn shared_transit_peer_attestation_obeys_one_absolute_deadline() {
    let fixture = Fixture::new();
    fixture
        .provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect("create peer for deadline test");
    fixture
        .engine
        .peer_inspection_delay_millis
        .store(5_000, Ordering::SeqCst);
    let started = Instant::now();
    let error = run_provider(ProviderStage::Inspect, async {
        fixture
            .provider
            .inner
            .verify_boundary_kind(
                &NeverCancelled,
                ResultsTransportBudget {
                    deadline: tokio::time::Instant::now() + Duration::from_millis(50),
                },
            )
            .await
            .map_err(|kind| known(kind, ProviderStage::Inspect))
    })
    .expect_err("the absolute attestation deadline must fail closed");

    assert_eq!(error.kind(), ProviderErrorKind::AdapterUnavailable);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the operation-wide deadline was not enforced"
    );
}

#[test]
fn shared_results_attestation_preserves_engine_failure_categories_and_custody() {
    for (engine_error, expected_kind) in engine_failure_categories() {
        let fixture = Fixture::new();
        let record = fixture
            .provider
            .create(&sandbox_spec(), &NeverCancelled)
            .expect("create Results topology");
        let mutations = fixture.engine.mutation_count();
        fixture.engine.mutate(|state| {
            state.next_results_transit_inspect_error = Some(engine_error);
        });

        let error = fixture
            .provider
            .inspect(record.handle(), &NeverCancelled)
            .expect_err("injected shared-attestation Engine failure");

        assert_eq!(error.kind(), expected_kind);
        assert_ne!(error.kind(), ProviderErrorKind::OwnershipMismatch);
        assert_eq!(error.outcome(), OperationOutcome::KnownNoEffect);
        assert!(error.recovery_handle().is_none());
        assert_eq!(fixture.engine.mutation_count(), mutations);
        assert_eq!(
            fixture
                .provider
                .inspect(record.handle(), &NeverCancelled)
                .expect("transient shared-attestation failure must retain custody")
                .state(),
            SandboxState::Running
        );
    }
}

#[test]
fn shared_transit_peer_attestation_is_concurrent_and_bounded() {
    let fixture = Fixture::new();
    let records = (1_u16..=33)
        .map(|slot| {
            fixture
                .provider
                .create(
                    &sandbox_spec_for_job_slot(400 + u128::from(slot), slot),
                    &NeverCancelled,
                )
                .expect("create attested transit peer")
        })
        .collect::<Vec<_>>();
    fixture
        .engine
        .maximum_peer_inspections_in_flight
        .store(0, Ordering::SeqCst);
    fixture
        .engine
        .peer_inspection_delay_millis
        .store(5, Ordering::SeqCst);

    fixture
        .provider
        .inspect(records[0].handle(), &NeverCancelled)
        .expect("bounded concurrent transit attestation");

    let maximum = fixture
        .engine
        .maximum_peer_inspections_in_flight
        .load(Ordering::SeqCst);
    assert_eq!(
        maximum, MAX_RESULTS_TRANSIT_ATTESTATION_CONCURRENCY,
        "peer attestation must saturate, but never exceed, its exact concurrency ceiling"
    );
}

#[test]
fn runner_and_slot_custody_bounds_fail_before_engine_access() {
    for custody in [
        SandboxCustody::Job {
            runner_id: RunnerId::new(),
            slot_ordinal: NonZeroU16::new(1).expect("slot"),
        },
        SandboxCustody::Job {
            runner_id: RunnerId::from_uuid(Uuid::from_u128(2)),
            slot_ordinal: NonZeroU16::new(crate::MAXIMUM_LOCAL_DOCKER_JOB_SLOTS + 1)
                .expect("out-of-range slot"),
        },
    ] {
        let fixture = Fixture::new();
        let spec = sandbox_spec_with_custody_and_resources(
            custody,
            ResourceLimits::new(256 * 1024 * 1024, 2_000, 128).expect("limits"),
        );
        let error = fixture
            .provider
            .create(&spec, &NeverCancelled)
            .expect_err("custody outside the provider contract");
        assert_eq!(error.kind(), ProviderErrorKind::UnsupportedCapability);
        assert_eq!(fixture.engine.access_count(), 0);
        assert_eq!(fixture.engine.mutation_count(), 0);
    }
}

#[test]
fn transit_capacity_duplicate_and_front_pool_overlap_fail_closed() {
    let fixture = Fixture::new();
    let transport = verified_results_transport(&fixture.installation);
    let state = fixture.engine.state.lock().expect("state");
    let base = state
        .networks
        .values()
        .find(|network| network.id == TRANSIT_NETWORK_ID)
        .expect("transit")
        .clone();
    drop(state);

    let mut undersized = base.clone();
    undersized.ipv4_network.prefix = 24;
    undersized
        .containers
        .get_mut(RESULTS_CONTAINER_ID)
        .expect("Results endpoint")
        .ipv4_prefix = 24;
    assert!(!exact_results_transit(
        &undersized,
        &fixture.installation,
        &transport.requested,
    ));

    let mut duplicate = base.clone();
    duplicate.containers.insert(
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
        NetworkEndpoint {
            name: "duplicate".to_owned(),
            endpoint_id: "edededededededededededededededededededededededededededededededed"
                .to_owned(),
            mac_address: "02:42:0a:5b:00:02".to_owned(),
            ipv4_address: transport.requested.results_address,
            ipv4_prefix: base.ipv4_network.prefix,
        },
    );
    assert!(!exact_results_transit(
        &duplicate,
        &fixture.installation,
        &transport.requested,
    ));

    let pool = results_front_pool(&fixture.installation);
    let mut overlapping = base;
    overlapping.ipv4_network = pool.clone();
    overlapping.ipv4_gateway = network_host_address(&pool, 1).expect("gateway");
    let results_address = network_host_address(&pool, 2).expect("Results address");
    overlapping
        .containers
        .get_mut(RESULTS_CONTAINER_ID)
        .expect("Results endpoint")
        .ipv4_address = results_address;
    overlapping
        .containers
        .get_mut(RESULTS_CONTAINER_ID)
        .expect("Results endpoint")
        .ipv4_prefix = pool.prefix;
    let mut requested = transport.requested;
    requested.results_address = results_address;
    assert!(!exact_results_transit(
        &overlapping,
        &fixture.installation,
        &requested,
    ));
}

#[test]
fn transit_drift_fails_before_any_sandbox_mutation() {
    let fixture = Fixture::new();
    fixture.engine.mutate(|state| {
        state
            .networks
            .values_mut()
            .find(|network| network.id == TRANSIT_NETWORK_ID)
            .expect("transit")
            .options
            .insert(
                "com.docker.network.bridge.gateway_mode_ipv4".to_owned(),
                "nat".to_owned(),
            );
    });
    let error = fixture
        .provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect_err("transit normalization drift");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(fixture.engine.mutation_count(), 0);
}

#[test]
fn duplicate_transit_endpoint_address_fails_before_any_sandbox_mutation() {
    let fixture = Fixture::new();
    fixture.engine.mutate(|state| {
        state
            .networks
            .values_mut()
            .find(|network| network.id == TRANSIT_NETWORK_ID)
            .expect("transit")
            .containers
            .insert(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
                NetworkEndpoint {
                    name: "duplicate".to_owned(),
                    endpoint_id: "edededededededededededededededededededededededededededededededed"
                        .to_owned(),
                    mac_address: "02:42:0a:5b:00:02".to_owned(),
                    ipv4_address: Ipv4Addr::new(10, 91, 0, 2),
                    ipv4_prefix: 16,
                },
            );
    });
    let error = fixture
        .provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect_err("duplicate transit endpoint address");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(fixture.engine.mutation_count(), 0);
}

#[test]
fn unavailable_results_target_fails_before_any_sandbox_mutation() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.results_target_running = false);
    let error = fixture
        .provider
        .create(&sandbox_spec(), &NeverCancelled)
        .expect_err("the pinned Results target must be running");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(fixture.engine.mutation_count(), 0);
}

#[test]
fn transit_peer_requires_the_full_closed_proxy_shape_except_for_custody_cleanup() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create sandbox");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    fixture.engine.mutate(|state| {
        state
            .containers
            .get_mut(&names.results_proxy)
            .expect("Results proxy")
            .definition
            .networks
            .insert(
                "automata-control".to_owned(),
                ContainerNetworkAttachment {
                    network_id: "1212121212121212121212121212121212121212121212121212121212121212"
                        .to_owned(),
                    ipv4_address: Ipv4Addr::new(10, 99, 0, 2),
                    aliases: Vec::new(),
                },
            );
    });
    let mutations_before = fixture.engine.mutation_count();
    let error = fixture
        .provider
        .inspect(record.handle(), &NeverCancelled)
        .expect_err("a proxy attached to any third network is not trusted");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(fixture.engine.mutation_count(), mutations_before);

    let destroy = DestroySandbox::new(
        OperationId::from_uuid(Uuid::from_u128(14)),
        record.handle().clone(),
        record.generation(),
        spec.custody(),
    );
    assert_eq!(
        fixture
            .provider
            .destroy(&destroy, &NeverCancelled)
            .expect("topology drift must not strand resources with exact custody"),
        DestroyDisposition::Destroyed
    );
}

#[test]
fn transit_peer_job_requires_full_container_identity_before_other_slot_mutation() {
    let fixture = Fixture::new();
    let first = sandbox_spec_for_job_slot(301, 1);
    fixture
        .provider
        .create(&first, &NeverCancelled)
        .expect("first slot");
    let first_names = ResourceNames::for_spec(&fixture.installation, &first).expect("first names");
    fixture.engine.mutate(|state| {
        let original_id = state
            .containers
            .get(&first_names.job)
            .expect("first job")
            .id
            .clone();
        replace_container(state, &original_id).expect("replace first job");
        let replacement = state
            .containers
            .get_mut(&first_names.job)
            .expect("replacement job");
        replacement.isolated = false;
        replacement
            .definition
            .environment
            .push("FOREIGN=true".to_owned());
    });
    let mutations_before = fixture.engine.mutation_count();
    let error = fixture
        .provider
        .create(&sandbox_spec_for_job_slot(302, 2), &NeverCancelled)
        .expect_err("foreign peer job identity");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(fixture.engine.mutation_count(), mutations_before);
}

#[test]
fn cached_peer_shape_is_reverified_after_later_peer_attestation() {
    let fixture = Fixture::new();
    let first = sandbox_spec_for_job_slot(311, 1);
    let second = sandbox_spec_for_job_slot(312, 2);
    fixture
        .provider
        .create(&first, &NeverCancelled)
        .expect("first slot");
    fixture
        .provider
        .create(&second, &NeverCancelled)
        .expect("second slot");
    let first_names = ResourceNames::for_spec(&fixture.installation, &first).expect("first names");
    let second_names =
        ResourceNames::for_spec(&fixture.installation, &second).expect("second names");
    fixture.engine.mutate(|state| {
        state.mutate_container_after_inspecting_name =
            Some((second_names.results_proxy.clone(), first_names.job.clone()));
    });
    let mutations_before = fixture.engine.mutation_count();
    let error = fixture
        .provider
        .create(&sandbox_spec_for_job_slot(313, 3), &NeverCancelled)
        .expect_err("cached first peer must be re-attested");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(fixture.engine.mutation_count(), mutations_before);
    assert!(
        !fixture
            .engine
            .container(&first_names.job)
            .expect("mutated first job")
            .isolated
    );
}

#[test]
fn foreign_front_network_collision_is_not_adopted_or_mutated() {
    let fixture = Fixture::new();
    let spec = sandbox_spec();
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    fixture.engine.mutate(|state| {
        let mut foreign = state
            .networks
            .values()
            .find(|network| network.id == TRANSIT_NETWORK_ID)
            .expect("transit")
            .clone();
        foreign.id = "edededededededededededededededededededededededededededededededed".to_owned();
        foreign.name = names.results_front.clone();
        foreign.labels.clear();
        foreign.containers.clear();
        state.networks.insert(names.results_front.clone(), foreign);
    });
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("foreign front collision");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(fixture.engine.mutation_count(), 0);
}

#[test]
fn matching_front_network_create_race_is_reinspected_and_replayed() {
    let fixture = Fixture::new();
    fixture
        .engine
        .mutate(|state| state.lose_next_network_create_response = true);
    let spec = sandbox_spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("post-inspected matching race winner");
    assert_eq!(record.state(), SandboxState::Running);
    let replay = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("exact topology replay");
    assert_eq!(replay, record);
}

#[test]
fn undersized_resource_limits_are_rejected_before_engine_access() {
    for resources in [
        ResourceLimits::new(
            MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES - 1,
            1_000,
            MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS,
        )
        .expect("low memory resources"),
        ResourceLimits::new(
            MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES,
            MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS - 1,
            MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS,
        )
        .expect("low CPU resources"),
        ResourceLimits::new(
            MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES,
            MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS,
            MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS - 1,
        )
        .expect("low PID resources"),
    ] {
        let fixture = Fixture::new();
        let accesses = fixture.engine.access_count();
        let error = fixture
            .provider
            .create(&sandbox_spec_with_resources(resources), &NeverCancelled)
            .expect_err("provider infrastructure minimum");
        assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
        assert_eq!(fixture.engine.access_count(), accesses);
        assert_eq!(fixture.engine.mutation_count(), 0);
    }
}

#[test]
fn exact_minimum_resource_limits_are_realized_without_hidden_headroom() {
    let fixture = Fixture::new();
    let spec = sandbox_spec_with_resources(
        ResourceLimits::new(
            MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES,
            MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS,
            MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS,
        )
        .expect("minimum resources"),
    );
    fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("minimum resources are supported");
    let names = ResourceNames::for_spec(&fixture.installation, &spec).expect("names");
    let job = fixture.engine.container(&names.job).expect("job");
    assert_eq!(
        job.definition.memory_bytes,
        i64::try_from(MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES).expect("minimum fits i64")
    );
    assert_eq!(
        job.definition.nano_cpus,
        i64::from(MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS) * 1_000_000
    );
    assert_eq!(
        job.definition.pids_limit,
        i64::from(MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS)
    );
}

#[test]
fn unsupported_spec_shape_is_rejected_before_engine_access() {
    let fixture = Fixture::new();
    let spec = sandbox_spec().with_privilege(SandboxPrivilegePolicy::Unprivileged);
    let accesses = fixture.engine.access_count();
    let error = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect_err("unsupported privilege");
    assert_eq!(error.kind(), ProviderErrorKind::UnsupportedCapability);
    assert_eq!(fixture.engine.access_count(), accesses);
    assert_eq!(fixture.engine.mutation_count(), 0);
}

#[test]
fn archive_builder_is_deterministic_and_contains_only_owned_paths() {
    let definition =
        sandbox_archive_definition("/workspace/repository").expect("archive definition");
    let first = sandbox_archive(&definition, FAKE_GUEST).expect("archive");
    let second = sandbox_archive(&definition, FAKE_GUEST).expect("archive");
    assert_eq!(first, second);
    assert_eq!(extract_uploaded_guest(&first).expect("guest"), FAKE_GUEST);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the fixed relay, an existing installation anchor, and digest-pinned local images"]
#[allow(clippy::too_many_lines)]
async fn fixed_relay_live_shell_and_javascript_conformance() {
    let installation_name = InstallationName::new(
        std::env::var("AUTOMATA_LOCAL_DOCKER_INSTALLATION")
            .expect("set the existing test installation name"),
    )
    .expect("installation name");
    let installation_id = InstallationId::parse_canonical(
        &std::env::var("AUTOMATA_LOCAL_DOCKER_INSTALLATION_ID")
            .expect("set the existing installation UUID"),
    )
    .expect("canonical installation UUID");
    let job_image = ImmutableImage::new(
        std::env::var("AUTOMATA_LOCAL_DOCKER_JOB_IMAGE")
            .expect("set a present digest-pinned Linux job image"),
    )
    .expect("job image");
    let guest_image = ImmutableImage::new(
        std::env::var("AUTOMATA_LOCAL_DOCKER_GUEST_IMAGE")
            .expect("set a present digest-pinned sandbox-guest image"),
    )
    .expect("guest image");
    let results_transport = LocalDockerResultsTransport::new(
        LocalImportedImage::new(
            std::env::var("AUTOMATA_LOCAL_DOCKER_RESULTS_PROXY_CONFIG_IMAGE_ID")
                .expect("set the imported Results proxy config image ID"),
            std::env::var("AUTOMATA_LOCAL_DOCKER_RESULTS_PROXY_MANIFEST_IMAGE_ID")
                .expect("set the imported Results proxy manifest image ID"),
        )
        .expect("Results proxy image"),
        Sha256Digest::from_str(
            &std::env::var("AUTOMATA_LOCAL_DOCKER_DESIRED_PLAN_SHA256")
                .expect("set the desired-plan SHA-256"),
        )
        .expect("desired-plan SHA-256"),
        std::env::var("AUTOMATA_LOCAL_DOCKER_RESULTS_TRANSIT_NETWORK_ID")
            .expect("set the exact Results transit network ID"),
        std::env::var("AUTOMATA_LOCAL_DOCKER_RESULTS_CONTAINER_ID")
            .expect("set the exact Results service container ID"),
        std::env::var("AUTOMATA_LOCAL_DOCKER_RESULTS_ADDRESS")
            .expect("set the exact private Results address")
            .parse()
            .expect("private Results IPv4 address"),
    )
    .expect("Results transport");
    assert!(
        std::path::Path::new(super::engine::LOCAL_DOCKER_RELAY_SOCKET).exists(),
        "install the explicit fixed Engine relay fixture"
    );
    let installation = crate::InstallationBinding::new(installation_name, installation_id);
    let runner_architecture = match normalize_architecture(std::env::consts::ARCH)
        .expect("the live fixture requires an amd64 or arm64 runner")
    {
        EngineArchitecture::Amd64 => automata_ci_core::Architecture::X86_64,
        EngineArchitecture::Arm64 => automata_ci_core::Architecture::Aarch64,
    };
    let runner_id = RunnerId::new();
    let provider = LocalDockerProvider::connect(
        installation,
        guest_image,
        results_transport,
        runner_id,
        &runner_architecture,
    )
    .await
    .expect("local Docker provider");
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.local/live-linux").expect("profile id"),
        Sha256Digest::from_str(PROFILE_DIGEST).expect("profile digest"),
    );
    let environment = automata_ci_execution::SandboxEnvironment::new(
        profile,
        job_image,
        ExecutionArgv::new(
            TargetPath::posix("/bin/sleep").expect("keepalive"),
            vec!["infinity".to_owned()],
        )
        .expect("keepalive argv"),
        TargetPath::posix("/workspace").expect("profile workspace"),
        ExecutionEnvironment::empty(),
    )
    .expect("environment");
    let generation = SandboxGeneration::new(1).expect("generation");
    let spec = SandboxSpec::new(
        OperationId::new(),
        generation,
        SandboxCustody::Job {
            runner_id,
            slot_ordinal: NonZeroU16::new(1).expect("slot"),
        },
        environment,
        TargetPath::posix("/workspace/repository").expect("workspace"),
        NetworkPolicy::PrivateEgress,
        RootFilesystemPolicy::Writable,
        ResourceLimits::new(512 * 1024 * 1024, 1_000, 128).expect("resources"),
    )
    .with_privilege(SandboxPrivilegePolicy::Administrator);
    let record = match provider.create(&spec, &NeverCancelled) {
        Ok(record) => record,
        Err(error) => {
            if let Some(handle) = error.recovery_handle().cloned()
                && let Err(cleanup_error) = provider.destroy(
                    &DestroySandbox::new(OperationId::new(), handle, generation, spec.custody()),
                    &NeverCancelled,
                )
            {
                panic!("create live sandbox: {error}; recovery cleanup failed: {cleanup_error}");
            }
            panic!("create live sandbox: {error}");
        }
    };
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<(), Box<dyn std::error::Error>> {
            let endpoint = provider.attach(record.handle(), &NeverCancelled)?;
            let attenuated_identity = ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::posix("/bin/sh")?,
                vec![
                    "-ceu".to_owned(),
                    concat!(
                        "test \"$(id -u):$(id -g)\" = 0:0; ",
                        "grep -Eq '^Uid:[[:space:]]+0[[:space:]]+0[[:space:]]+0[[:space:]]+0$' /proc/self/status; ",
                        "grep -Eq '^Gid:[[:space:]]+0[[:space:]]+0[[:space:]]+0[[:space:]]+0$' /proc/self/status; ",
                        "grep -Eq '^Groups:[[:space:]]+0[[:space:]]*$' /proc/self/status; ",
                        "for field in CapInh CapPrm CapEff CapBnd CapAmb; do ",
                        "grep -Eq \"^${field}:[[:space:]]+0000000000000000$\" /proc/self/status; done; ",
                        "grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status; ",
                        "grep -Eq '^Seccomp:[[:space:]]+2$' /proc/self/status; ",
                        "for map in /proc/self/uid_map /proc/self/gid_map; do ",
                        "test \"$(wc -l < \"${map}\")\" -eq 1; set -- $(cat \"${map}\"); ",
                        "test \"$#\" -eq 3; test \"$1\" -eq 0; test \"$2\" -gt 0; ",
                        "test \"$3\" -gt 65533; done; printf attenuated-live"
                    )
                    .to_owned(),
                ],
            )?,
            spec.workspace().clone(),
            ExecutionEnvironment::empty(),
            Duration::from_secs(10),
            64 * 1024,
        )?;
            let output = endpoint.exec(
                &attenuated_identity,
                &NeverCancelled,
                automata_ci_execution::discard_execution_output(),
            )?;
            assert_eq!(output.termination(), ExecutionTermination::Exited(0));
            assert_eq!(output.stdout(), b"attenuated-live");

            for (program, arguments, expected) in [
                (
                    "/bin/bash",
                    vec!["-c".to_owned(), "printf shell-live".to_owned()],
                    b"shell-live".as_slice(),
                ),
                (
                    "/usr/bin/node",
                    vec![
                        "-e".to_owned(),
                        "process.stdout.write('node-live')".to_owned(),
                    ],
                    b"node-live".as_slice(),
                ),
            ] {
                let command = ExecutionCommand::new(
                    OperationId::new(),
                    ExecutionArgv::new(TargetPath::posix(program)?, arguments)?,
                    spec.workspace().clone(),
                    ExecutionEnvironment::empty(),
                    Duration::from_secs(10),
                    64 * 1024,
                )?;
                let output = endpoint.exec(
                    &command,
                    &NeverCancelled,
                    automata_ci_execution::discard_execution_output(),
                )?;
                assert_eq!(output.termination(), ExecutionTermination::Exited(0));
                assert_eq!(output.stdout(), expected);
            }

            let protected_envelope = ExecutionCommand::new(
                OperationId::new(),
                ExecutionArgv::new(
                    TargetPath::posix("/bin/bash")?,
                    vec![
                        "-c".to_owned(),
                        format!(
                            "set -eu; test \"$(stat -c '%u:%g:%a' {directory})\" = '{seal_uid}:{gid}:{sealed_mode:o}'; ! dd if={client} of=/dev/null status=none 2>/dev/null; ! chmod 0700 {client} 2>/dev/null; ! sh -c 'printf tamper > {client}' 2>/dev/null; ! readlink /proc/1/exe >/dev/null 2>&1; kill -KILL 1; sleep 0.1; test -d /proc/1; printf protected-live",
                            directory = LOCAL_CONTROL_DIRECTORY,
                            seal_uid = LOCAL_CONTROL_SEAL_UID,
                            gid = LOCAL_CONTROL_GID,
                            sealed_mode =
                                automata_ci_sandbox_guest::LOCAL_CONTROL_DIRECTORY_MODE_SEALED,
                            client = LOCAL_CONTROL_CLIENT,
                        ),
                    ],
                )?,
                spec.workspace().clone(),
                ExecutionEnvironment::empty(),
                Duration::from_secs(10),
                64 * 1024,
            )?;
            let output = endpoint.exec(
                &protected_envelope,
                &NeverCancelled,
                automata_ci_execution::discard_execution_output(),
            )?;
            assert_eq!(output.termination(), ExecutionTermination::Exited(0));
            assert_eq!(output.stdout(), b"protected-live");

            let direct_broker = ExecutionCommand::new(
                OperationId::new(),
                ExecutionArgv::new(
                    TargetPath::posix("/usr/bin/node")?,
                    vec![
                    "-e".to_owned(),
                    concat!(
                        "const net=require('net');",
                        "const body=Buffer.from(JSON.stringify({operation:'probe',",
                        "protocol:3,operation_id:'untrusted-root-direct-probe'}));",
                        "const frame=Buffer.alloc(4+body.length);",
                        "frame.writeUInt32BE(body.length);body.copy(frame,4);",
                        "const socket=net.createConnection({path:'\\0automata-ci-control-v1'});",
                        "let received=0;socket.on('connect',()=>socket.end(frame));",
                        "socket.on('data',chunk=>received+=chunk.length);",
                        "socket.on('close',()=>process.exit(received===0?0:1));",
                        "socket.on('error',()=>process.exit(0));",
                        "setTimeout(()=>process.exit(1),1000)"
                    )
                    .to_owned(),
                ],
                )?,
                spec.workspace().clone(),
                ExecutionEnvironment::empty(),
                Duration::from_secs(5),
                64 * 1024,
            )?;
            assert_eq!(
                endpoint
                    .exec(
                        &direct_broker,
                        &NeverCancelled,
                        automata_ci_execution::discard_execution_output()
                    )?
                    .termination(),
                ExecutionTermination::Exited(0),
                "capless root must not receive a broker response"
            );

            let network_gate = ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::posix("/usr/bin/node")?,
                vec![
                    "-e".to_owned(),
                    concat!(
                        "const dns=require('dns');const net=require('net');",
                        "const fail=(m)=>{console.error(m);process.exit(1)};",
                        "const timeout=(p)=>Promise.race([p,new Promise((_,r)=>setTimeout(()=>r(new Error('timeout')),2000))]);",
                        "const connect=(host,port,request)=>timeout(new Promise((resolve,reject)=>{",
                        "const s=net.createConnection({host,port});let n=0;",
                        "s.on('connect',()=>{if(request)s.write('GET / HTTP/1.0\\r\\nHost: results.automata.invalid\\r\\n\\r\\n')});",
                        "s.on('data',b=>{n+=b.length;s.destroy()});s.on('close',()=>n?resolve():reject(new Error('empty')));",
                        "s.on('error',reject)}));",
                        "(async()=>{await connect('results.automata.invalid',8081,true);",
                        "let externalDns=false;try{await timeout(dns.promises.resolve4('example.com'));externalDns=true}catch{}",
                        "if(externalDns)fail('external DNS escaped');",
                        "let internet=false;try{await connect('1.1.1.1',80,false);internet=true}catch{}",
                        "if(internet)fail('public egress escaped');process.stdout.write('closed-results-live')})().catch(e=>fail(e.message));"
                    )
                    .to_owned(),
                ],
            )?,
            spec.workspace().clone(),
            ExecutionEnvironment::empty(),
            Duration::from_secs(10),
            64 * 1024,
        )?;
            let output = endpoint.exec(
                &network_gate,
                &NeverCancelled,
                automata_ci_execution::discard_execution_output(),
            )?;
            assert_eq!(output.termination(), ExecutionTermination::Exited(0));
            assert_eq!(output.stdout(), b"closed-results-live");

            let forbidden_bootstrap = ExecutionCommand::new(
                OperationId::new(),
                ExecutionArgv::new(
                    TargetPath::posix(LOCAL_DOCKER_SANDBOX_GUEST_BINARY)?,
                    vec!["bootstrap-local-client".to_owned()],
                )?,
                spec.workspace().clone(),
                ExecutionEnvironment::empty(),
                Duration::from_secs(5),
                64 * 1024,
            )?;
            assert_eq!(
                endpoint
                    .exec(
                        &forbidden_bootstrap,
                        &NeverCancelled,
                        automata_ci_execution::discard_execution_output()
                    )?
                    .termination(),
                ExecutionTermination::Exited(1),
                "capless root cannot reopen the one-shot sealer"
            );

            let after_signal = ExecutionCommand::new(
                OperationId::new(),
                ExecutionArgv::new(
                    TargetPath::posix("/bin/bash")?,
                    vec!["-c".to_owned(), "printf broker-still-ready".to_owned()],
                )?,
                spec.workspace().clone(),
                ExecutionEnvironment::empty(),
                Duration::from_secs(5),
                64 * 1024,
            )?;
            let output = endpoint.exec(
                &after_signal,
                &NeverCancelled,
                automata_ci_execution::discard_execution_output(),
            )?;
            assert_eq!(output.termination(), ExecutionTermination::Exited(0));
            assert_eq!(output.stdout(), b"broker-still-ready");
            Ok(())
        },
    ));
    let cleanup = provider.destroy(
        &DestroySandbox::new(
            OperationId::new(),
            record.handle().clone(),
            generation,
            spec.custody(),
        ),
        &NeverCancelled,
    );
    match run {
        Ok(run) => {
            cleanup.expect("destroy exact live sandbox");
            run.expect("live shell and JavaScript conformance");
        }
        Err(payload) => {
            if let Err(error) = cleanup {
                eprintln!("live fixture cleanup after panic failed: {error}");
            }
            std::panic::resume_unwind(payload);
        }
    }
}
