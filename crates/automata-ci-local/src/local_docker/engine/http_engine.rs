use std::{collections::BTreeMap, time::Duration};

use std::path::Path;

use async_trait::async_trait;
use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use serde::de::IgnoredAny;

use super::{
    ContainerDefinition, EngineContainerState, EngineExecOutput, EngineExecRequest,
    InspectedContainer, InspectedContainerCustody, InspectedImage,
    LOCAL_DOCKER_GUEST_ARCHIVE_BYTES, LOCAL_DOCKER_GUEST_IMAGE_BINARY,
    LOCAL_DOCKER_SANDBOX_GUEST_BINARY, PreparedEngineExec, SandboxEngineApi,
};
use super::{
    EngineApi, EngineApiError, EngineFacts, InspectedVolume,
    transport::{
        BoundedMap, BoundedVec, DockerHttpTransport, TransportError, deadline,
        encode_path_component,
    },
};
use crate::{ApiVersion, normalize_architecture};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const FACTS_BYTES: usize = 128 * 1024;
const VOLUME_BYTES: usize = 256 * 1024;
const CONTAINER_LIST_BYTES: usize = 256 * 1024;
const MAX_ATTACHMENTS: usize = 8;
const MAX_LABELS: usize = 256;
const MAX_VOLUME_OPTIONS: usize = 32;
#[cfg(unix)]
const IMAGE_BYTES: usize = 512 * 1024;
#[cfg(unix)]
const CONTAINER_BYTES: usize = 512 * 1024;
#[cfg(unix)]
const EXEC_BYTES: usize = 128 * 1024;
#[cfg(unix)]
const MAX_REPO_DIGESTS: usize = 128;
#[cfg(unix)]
const MAX_DECLARED_VOLUMES: usize = 64;
#[cfg(unix)]
const MAX_MOUNTS: usize = 16;
#[cfg(unix)]
const MAX_ENVIRONMENT: usize = 256;
#[cfg(unix)]
const MAX_ARGUMENTS: usize = 256;
#[cfg(unix)]
const MAX_NETWORKS: usize = 8;
#[cfg(unix)]
const MAX_SECURITY_OPTIONS: usize = 16;
#[cfg(unix)]
const MAX_DEVICES: usize = 64;
#[cfg(unix)]
const SHM_BYTES: i64 = 64 * 1024 * 1024;
#[cfg(unix)]
const MASKED_PATHS: &[&str] = &[
    "/proc/acpi",
    "/proc/asound",
    "/proc/interrupts",
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
#[cfg(unix)]
const READ_ONLY_PATHS: &[&str] = &[
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
];
#[cfg(unix)]
const ARCHIVE_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) struct HttpEngine {
    transport: DockerHttpTransport,
}

impl HttpEngine {
    pub(super) fn connect_unix_socket(
        socket: &Path,
        api: ApiVersion,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            transport: DockerHttpTransport::connect_unix_socket(socket, api)?,
        })
    }
}

#[async_trait]
impl EngineApi for HttpEngine {
    async fn engine_facts(&self) -> Result<EngineFacts, EngineApiError> {
        let (info, version) = deadline(REQUEST_TIMEOUT, async {
            tokio::try_join!(
                self.transport.json::<InfoResponse, ()>(
                    Method::GET,
                    "/info",
                    None,
                    StatusCode::OK,
                    FACTS_BYTES,
                ),
                self.transport.json::<VersionResponse, ()>(
                    Method::GET,
                    "/version",
                    None,
                    StatusCode::OK,
                    FACTS_BYTES,
                )
            )
        })
        .await
        .map_err(map_transport)?;
        let info_architecture =
            normalize_architecture(&info.architecture).ok_or(EngineApiError::InvalidResponse)?;
        let version_architecture =
            normalize_architecture(&version.architecture).ok_or(EngineApiError::InvalidResponse)?;
        if info.id.is_empty()
            || info.server_version != version.version
            || info_architecture != version_architecture
            || info.operating_system != version.operating_system
        {
            return Err(EngineApiError::InvalidResponse);
        }
        let mut security_options = info
            .security_options
            .map(BoundedVec::into_inner)
            .unwrap_or_default();
        security_options.sort();
        Ok(EngineFacts {
            engine_id: info.id,
            server_version: version.version,
            minimum_api_version: version.minimum_api_version,
            maximum_api_version: version.api_version,
            operating_system: version.operating_system,
            architecture: version.architecture,
            security_options,
            memory_limit: info.memory_limit,
            swap_limit: info.swap_limit,
            cpu_cfs_period: info.cpu_cfs_period,
            cpu_cfs_quota: info.cpu_cfs_quota,
            pids_limit: info.pids_limit,
        })
    }
}

#[async_trait]
impl super::AnchorEngineApi for HttpEngine {
    async fn inspect_volume(&self, name: &str) -> Result<Option<InspectedVolume>, EngineApiError> {
        let path = format!("/volumes/{}", encode_path_component(name));
        let volume: Option<VolumeResponse> = deadline(
            REQUEST_TIMEOUT,
            self.transport.optional_json(&path, VOLUME_BYTES),
        )
        .await
        .map_err(map_transport)?;
        Ok(volume.map(|volume| InspectedVolume {
            name: volume.name,
            driver: volume.driver,
            scope: volume.scope,
            options: volume
                .options
                .map_or_else(BTreeMap::new, BoundedMap::into_inner),
            labels: volume
                .labels
                .map_or_else(BTreeMap::new, BoundedMap::into_inner),
        }))
    }

    async fn volume_attachments(&self, name: &str) -> Result<Vec<String>, EngineApiError> {
        let filters = serde_json::to_string(&BTreeMap::from([("volume", [name])]))
            .map_err(|_| EngineApiError::InvalidResponse)?;
        let path = format!(
            "/containers/json?all=true&filters={}",
            encode_path_component(&filters)
        );
        let containers: BoundedVec<ContainerSummary, MAX_ATTACHMENTS> = deadline(
            REQUEST_TIMEOUT,
            self.transport.json::<_, ()>(
                Method::GET,
                &path,
                None,
                StatusCode::OK,
                CONTAINER_LIST_BYTES,
            ),
        )
        .await
        .map_err(map_transport)?;
        containers
            .into_inner()
            .into_iter()
            .map(|container| {
                if valid_object_id(&container.id) {
                    Ok(container.id)
                } else {
                    Err(EngineApiError::InvalidResponse)
                }
            })
            .collect()
    }
}

#[async_trait]
impl SandboxEngineApi for HttpEngine {
    async fn inspect_image(
        &self,
        reference: &str,
    ) -> Result<Option<InspectedImage>, EngineApiError> {
        let path = format!("/images/{}/json", encode_path_component(reference));
        let image: Option<ImageResponse> = deadline(
            REQUEST_TIMEOUT,
            self.transport.optional_json(&path, IMAGE_BYTES),
        )
        .await
        .map_err(map_transport)?;
        image.map(normalize_image).transpose()
    }

    async fn inspect_container(
        &self,
        name: &str,
    ) -> Result<Option<InspectedContainer>, EngineApiError> {
        let path = format!(
            "/containers/{}/json?size=false",
            encode_path_component(name)
        );
        let container: Option<ContainerResponse> = deadline(
            REQUEST_TIMEOUT,
            self.transport.optional_json(&path, CONTAINER_BYTES),
        )
        .await
        .map_err(map_transport)?;
        container.map(normalize_container).transpose()
    }

    async fn inspect_container_custody(
        &self,
        name_or_id: &str,
    ) -> Result<Option<InspectedContainerCustody>, EngineApiError> {
        let path = format!(
            "/containers/{}/json?size=false",
            encode_path_component(name_or_id)
        );
        let container: Option<ContainerCustodyResponse> = deadline(
            REQUEST_TIMEOUT,
            self.transport.optional_json(&path, CONTAINER_BYTES),
        )
        .await
        .map_err(map_transport)?;
        container.map(normalize_container_custody).transpose()
    }

    async fn create_container(
        &self,
        definition: ContainerDefinition,
    ) -> Result<(), EngineApiError> {
        let path = format!(
            "/containers/create?name={}",
            encode_path_component(&definition.name)
        );
        let body = ContainerCreateRequest::new(&definition);
        let created: ContainerCreateResponse = deadline(
            REQUEST_TIMEOUT,
            self.transport.json(
                Method::POST,
                &path,
                Some(&body),
                StatusCode::CREATED,
                EXEC_BYTES,
            ),
        )
        .await
        .map_err(map_transport)?;
        if !valid_object_id(&created.id)
            || created
                .warnings
                .is_some_and(|warnings| !warnings.into_inner().is_empty())
        {
            return Err(EngineApiError::InvalidResponse);
        }
        Ok(())
    }

    async fn start_container(&self, id: &str) -> Result<(), EngineApiError> {
        require_object_id(id)?;
        let path = format!("/containers/{}/start", encode_path_component(id));
        deadline(
            REQUEST_TIMEOUT,
            self.transport
                .empty(Method::POST, &path, StatusCode::NO_CONTENT),
        )
        .await
        .map_err(map_transport)
    }

    async fn remove_container(&self, id: &str) -> Result<(), EngineApiError> {
        require_object_id(id)?;
        // Cleanup may encounter a dead or otherwise uninspectable runtime.
        // The provider calls this only after revalidating the exact immutable
        // custody ID and managed-label snapshot by both name and ID.
        let path = format!(
            "/containers/{}?force=true&v=false&link=false",
            encode_path_component(id)
        );
        deadline(
            REQUEST_TIMEOUT,
            self.transport
                .empty_or_not_found(Method::DELETE, &path, StatusCode::NO_CONTENT),
        )
        .await
        .map_err(map_transport)
    }

    async fn kill_container(&self, id: &str) -> Result<(), EngineApiError> {
        require_object_id(id)?;
        let path = format!("/containers/{}/kill?signal=KILL", encode_path_component(id));
        deadline(
            REQUEST_TIMEOUT,
            self.transport
                .empty(Method::POST, &path, StatusCode::NO_CONTENT),
        )
        .await
        .map_err(map_transport)
    }

    async fn download_guest_image_binary(
        &self,
        id: &str,
        byte_limit: usize,
    ) -> Result<Vec<u8>, EngineApiError> {
        require_object_id(id)?;
        if byte_limit == 0 || byte_limit > LOCAL_DOCKER_GUEST_ARCHIVE_BYTES {
            return Err(EngineApiError::OutputLimit);
        }
        let path = format!(
            "/containers/{}/archive?path={}",
            encode_path_component(id),
            encode_path_component(LOCAL_DOCKER_GUEST_IMAGE_BINARY)
        );
        deadline(
            ARCHIVE_TIMEOUT,
            self.transport.bytes(&path, "application/x-tar", byte_limit),
        )
        .await
        .map_err(map_transport)
    }

    async fn download_sandbox_guest(
        &self,
        id: &str,
        byte_limit: usize,
    ) -> Result<Vec<u8>, EngineApiError> {
        require_object_id(id)?;
        if byte_limit == 0 || byte_limit > LOCAL_DOCKER_GUEST_ARCHIVE_BYTES {
            return Err(EngineApiError::OutputLimit);
        }
        let path = format!(
            "/containers/{}/archive?path={}",
            encode_path_component(id),
            encode_path_component(LOCAL_DOCKER_SANDBOX_GUEST_BINARY)
        );
        deadline(
            ARCHIVE_TIMEOUT,
            self.transport.bytes(&path, "application/x-tar", byte_limit),
        )
        .await
        .map_err(map_transport)
    }

    async fn upload_sandbox_archive(&self, id: &str, archive: &[u8]) -> Result<(), EngineApiError> {
        require_object_id(id)?;
        let path = format!(
            "/containers/{}/archive?path=%2F&noOverwriteDirNonDir=true&copyUIDGID=false",
            encode_path_component(id)
        );
        deadline(
            ARCHIVE_TIMEOUT,
            self.transport.empty_bytes(
                Method::PUT,
                &path,
                "application/x-tar",
                archive,
                LOCAL_DOCKER_GUEST_ARCHIVE_BYTES,
                StatusCode::OK,
            ),
        )
        .await
        .map_err(map_transport)
    }

    async fn create_exec(
        &self,
        container_id: &str,
        command: &[String],
        user: &str,
    ) -> Result<PreparedEngineExec, EngineApiError> {
        require_object_id(container_id)?;
        if command.is_empty()
            || command.len() > MAX_ARGUMENTS
            || user.is_empty()
            || user.len() > 128
        {
            return Err(EngineApiError::InvalidResponse);
        }
        let create_path = format!("/containers/{}/exec", encode_path_component(container_id));
        let created: ExecCreateResponse = deadline(
            REQUEST_TIMEOUT,
            self.transport.json(
                Method::POST,
                &create_path,
                Some(&ExecCreateRequest {
                    attach_stdin: true,
                    attach_stdout: true,
                    attach_stderr: true,
                    tty: false,
                    environment: Vec::new(),
                    command: command.to_vec(),
                    privileged: false,
                    user,
                }),
                StatusCode::CREATED,
                EXEC_BYTES,
            ),
        )
        .await
        .map_err(map_transport)?;
        require_object_id(&created.id)?;
        let inspect_path = format!("/exec/{}/json", encode_path_component(&created.id));
        let inspected: ExecInspectResponse = deadline(
            REQUEST_TIMEOUT,
            self.transport.json::<_, ()>(
                Method::GET,
                &inspect_path,
                None,
                StatusCode::OK,
                EXEC_BYTES,
            ),
        )
        .await
        .map_err(map_transport)?;
        if !inspected.matches_created(&created.id, container_id, command, user) {
            return Err(EngineApiError::InvalidResponse);
        }
        Ok(PreparedEngineExec {
            id: created.id,
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
        if prepared.container_id != request.container_id
            || prepared.command != request.command
            || prepared.user != request.user
        {
            return Err(EngineApiError::InvalidResponse);
        }
        tokio::time::timeout(request.timeout, self.start_exec_inner(prepared, request))
            .await
            .map_err(|_| EngineApiError::RequestFailed)?
    }
}

#[cfg(unix)]
impl HttpEngine {
    async fn start_exec_inner(
        &self,
        prepared: &PreparedEngineExec,
        request: &EngineExecRequest,
    ) -> Result<EngineExecOutput, EngineApiError> {
        require_object_id(&request.container_id)?;
        require_object_id(&prepared.id)?;
        let start_path = format!("/exec/{}/start", encode_path_component(&prepared.id));
        let raw_limit = request
            .stdout_limit
            .checked_add(request.stderr_limit)
            .and_then(|value| value.checked_add(8 * 1024))
            .ok_or(EngineApiError::OutputLimit)?;
        let bytes = self
            .transport
            .hijack_json(
                &start_path,
                &ExecStartRequest {
                    detach: false,
                    tty: false,
                },
                request.stdin.as_slice(),
                raw_limit,
            )
            .await
            .map_err(map_transport)?;
        let (stdout, stderr) =
            decode_multiplexed(&bytes, request.stdout_limit, request.stderr_limit)?;
        let inspect_path = format!("/exec/{}/json", encode_path_component(&prepared.id));
        let inspected: ExecInspectResponse = self
            .transport
            .json::<_, ()>(Method::GET, &inspect_path, None, StatusCode::OK, EXEC_BYTES)
            .await
            .map_err(map_transport)?;
        if !inspected.matches_finished(prepared, request) {
            return Err(EngineApiError::InvalidResponse);
        }
        Ok(EngineExecOutput {
            stdout,
            stderr,
            exit_code: inspected.exit_code.ok_or(EngineApiError::InvalidResponse)?,
        })
    }
}

const fn map_transport(error: TransportError) -> EngineApiError {
    match error {
        TransportError::InvalidRequest
        | TransportError::InvalidResponse
        | TransportError::ResponseTooLarge => EngineApiError::InvalidResponse,
        TransportError::RequestFailed | TransportError::Rejected(_) => {
            EngineApiError::RequestFailed
        }
    }
}

fn valid_object_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn require_object_id(value: &str) -> Result<(), EngineApiError> {
    if valid_object_id(value) {
        Ok(())
    } else {
        Err(EngineApiError::InvalidResponse)
    }
}

#[cfg(unix)]
fn normalize_image(response: ImageResponse) -> Result<InspectedImage, EngineApiError> {
    require_image_id(&response.id)?;
    let mut repo_digests = response.repo_digests.into_inner();
    repo_digests.sort();
    if repo_digests.is_empty() || repo_digests.iter().any(String::is_empty) {
        return Err(EngineApiError::InvalidResponse);
    }
    let mut declared_volumes = response.config.volumes.map_or_else(Vec::new, |volumes| {
        volumes.into_inner().into_keys().collect()
    });
    declared_volumes.sort();
    let mut declared_exposed_ports = response
        .config
        .exposed_ports
        .map_or_else(Vec::new, |ports| ports.into_inner().into_keys().collect());
    declared_exposed_ports.sort();
    let mut environment_names = response
        .config
        .environment
        .map_or_else(Vec::new, BoundedVec::into_inner)
        .into_iter()
        .map(|entry| {
            let (name, _) = entry
                .split_once('=')
                .ok_or(EngineApiError::InvalidResponse)?;
            if !valid_environment_name(name) {
                return Err(EngineApiError::InvalidResponse);
            }
            Ok(name.to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    environment_names.sort();
    if environment_names
        .windows(2)
        .any(|names| names[0] == names[1])
    {
        return Err(EngineApiError::InvalidResponse);
    }
    Ok(InspectedImage {
        id: response.id,
        repo_digests,
        operating_system: response.operating_system,
        architecture: response.architecture,
        declared_volumes,
        declared_exposed_ports,
        has_healthcheck: response.config.healthcheck.is_some(),
        labels: response
            .config
            .labels
            .map_or_else(BTreeMap::new, BoundedMap::into_inner),
        environment_names,
    })
}

#[cfg(unix)]
fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(unix)]
fn require_image_id(value: &str) -> Result<(), EngineApiError> {
    value
        .strip_prefix("sha256:")
        .filter(|digest| valid_object_id(digest))
        .map_or(Err(EngineApiError::InvalidResponse), |_| Ok(()))
}

#[cfg(unix)]
fn normalize_container(response: ContainerResponse) -> Result<InspectedContainer, EngineApiError> {
    require_object_id(&response.id)?;
    require_image_id(&response.image_id)?;
    if response.restart_count != 0
        || response.driver.is_empty()
        || response.platform != "linux"
        || !response.mount_label.is_empty()
        || !response.process_label.is_empty()
        || !response.app_armor_profile.is_empty()
        || !response.log_path.is_empty()
    {
        return Err(EngineApiError::InvalidResponse);
    }
    if let Some(exec_ids) = response.exec_ids.as_ref() {
        // Docker transiently exposes active Engine execs here. They are daemon
        // bookkeeping rather than container configuration: every operation is
        // separately pinned to its exact exec and container IDs. Still accept
        // only the bounded, canonical, unique form produced by the daemon.
        if exec_ids.as_slice().iter().enumerate().any(|(index, id)| {
            !valid_object_id(id)
                || exec_ids
                    .as_slice()
                    .iter()
                    .skip(index + 1)
                    .any(|other| other == id)
        }) {
            return Err(EngineApiError::InvalidResponse);
        }
    }
    let name = response
        .name
        .strip_prefix('/')
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .ok_or(EngineApiError::InvalidResponse)?
        .to_owned();
    let config = response.config;
    let host = response.host_config;
    let entrypoint = config.entrypoint.as_slice();
    if entrypoint.len() != 1 {
        return Err(EngineApiError::InvalidResponse);
    }
    let entrypoint = entrypoint[0].clone();
    if host
        .mounts
        .as_ref()
        .is_some_and(|mounts| !mounts.is_empty())
        || !response.mounts.is_empty()
    {
        return Err(EngineApiError::InvalidResponse);
    }
    let state = normalized_container_state(&response.state);
    let expected_hostname = response
        .id
        .get(..12)
        .ok_or(EngineApiError::InvalidResponse)?;
    let path_matches = response.path == entrypoint && response.arguments == config.command;
    let isolated = path_matches
        && exact_isolation(
            &config,
            &host,
            &response.network_settings,
            expected_hostname,
        );
    Ok(InspectedContainer {
        id: response.id,
        image_id: response.image_id,
        definition: ContainerDefinition {
            name,
            image: config.image,
            entrypoint,
            arguments: config.command.into_inner(),
            labels: config.labels.into_inner(),
            environment: config.environment.into_inner(),
            tmpfs: host
                .tmpfs
                .map_or_else(BTreeMap::new, BoundedMap::into_inner),
            working_directory: config.working_directory,
            user: config.user,
            read_only_root: host.read_only_root,
            memory_bytes: host.memory_bytes,
            nano_cpus: host.nano_cpus,
            pids_limit: host.pids_limit,
        },
        state,
        isolated,
    })
}

#[cfg(unix)]
fn normalize_container_custody(
    response: ContainerCustodyResponse,
) -> Result<InspectedContainerCustody, EngineApiError> {
    require_object_id(&response.id)?;
    require_image_id(&response.image_id)?;
    let name = response
        .name
        .strip_prefix('/')
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .ok_or(EngineApiError::InvalidResponse)?
        .to_owned();
    let state = match (
        response.state.status.as_str(),
        response.state.running,
        response.state.exit_code,
    ) {
        ("created", false, 0) => EngineContainerState::Created,
        ("running", true, 0) => EngineContainerState::Running,
        ("exited", false, exit_code) => EngineContainerState::Exited(exit_code),
        _ => EngineContainerState::Invalid,
    };
    Ok(InspectedContainerCustody {
        id: response.id,
        image_id: response.image_id,
        name,
        image: response.config.image,
        labels: response
            .config
            .labels
            .map_or_else(BTreeMap::new, BoundedMap::into_inner),
        state,
    })
}

#[cfg(unix)]
fn normalized_container_state(state: &ContainerStateResponse) -> EngineContainerState {
    let common = !state.paused && !state.restarting && !state.dead && state.health.is_none();
    match state.status.as_str() {
        "created"
            if common
                && !state.running
                && !state.out_of_memory
                && state.pid == 0
                && state.exit_code == 0
                && state.error.is_empty() =>
        {
            EngineContainerState::Created
        }
        "running"
            if common
                && state.running
                && !state.out_of_memory
                && state.pid > 0
                && state.exit_code == 0
                && state.error.is_empty() =>
        {
            EngineContainerState::Running
        }
        "exited" if common && !state.running && state.pid == 0 => {
            EngineContainerState::Exited(state.exit_code)
        }
        _ => EngineContainerState::Invalid,
    }
}

#[cfg(unix)]
fn exact_isolation(
    config: &ContainerConfigResponse,
    host: &HostConfigResponse,
    network: &NetworkSettingsResponse,
    expected_hostname: &str,
) -> bool {
    exact_container_config(config, expected_hostname)
        && exact_host_runtime(host)
        && exact_host_scheduling(host)
        && exact_host_memory(host)
        && exact_host_resource_surface(host)
        && exact_host_paths(host)
        && exact_network(network)
}

#[cfg(unix)]
fn exact_container_config(config: &ContainerConfigResponse, expected_hostname: &str) -> bool {
    config.hostname == expected_hostname
        && config.domain_name.is_empty()
        && !config.attach_stdin
        && !config.attach_stdout
        && !config.attach_stderr
        && !config.tty
        && !config.open_stdin
        && !config.stdin_once
        && config.args_escaped.is_none_or(|escaped| !escaped)
        && config.on_build.as_ref().is_none_or(BoundedVec::is_empty)
        && config.shell.as_ref().is_none_or(BoundedVec::is_empty)
        && valid_neutral_environment(config.environment.as_slice())
        && config.volumes.as_ref().is_none_or(BoundedMap::is_empty)
        && config
            .exposed_ports
            .as_ref()
            .is_none_or(BoundedMap::is_empty)
        && config.network_disabled
        && config.healthcheck.is_disabled()
        && config.stop_signal == "SIGKILL"
        && config.stop_timeout == Some(0)
        && config.mac_address.as_ref().is_none_or(String::is_empty)
}

#[cfg(unix)]
fn exact_host_runtime(host: &HostConfigResponse) -> bool {
    host.binds.as_ref().is_none_or(BoundedVec::is_empty)
        && host.container_id_file.is_empty()
        && host.network_mode == "none"
        && host.port_bindings.is_empty()
        && host.restart_policy.name == "no"
        && host.restart_policy.maximum_retry_count == 0
        && !host.auto_remove
        && host.volume_driver.is_empty()
        && host.volumes_from.as_ref().is_none_or(BoundedVec::is_empty)
        && host.cap_add.as_ref().is_none_or(BoundedVec::is_empty)
        && host.cap_drop.as_slice() == ["ALL"]
        && host.cgroup_namespace_mode == "private"
        && host.dns.as_ref().is_none_or(BoundedVec::is_empty)
        && host.dns_options.is_empty()
        && host.dns_search.is_empty()
        && host.extra_hosts.as_ref().is_none_or(BoundedVec::is_empty)
        && host.group_add.as_ref().is_none_or(BoundedVec::is_empty)
        && host.ipc_mode == "private"
        && host.cgroup.is_empty()
        && host.links.as_ref().is_none_or(BoundedVec::is_empty)
        && host.oom_score_adjustment == 0
        && host.pid_mode.is_empty()
        && !host.privileged
        && !host.publish_all_ports
        && host.security_options.as_slice() == ["no-new-privileges=true", "seccomp=builtin"]
        && host.uts_mode.is_empty()
        && host.user_namespace_mode.is_empty()
        && host.runtime == "runc"
        && host.isolation.is_empty()
        && host.shm_bytes == SHM_BYTES
        && host.console_size == [0, 0]
}

#[cfg(unix)]
fn exact_host_scheduling(host: &HostConfigResponse) -> bool {
    host.cpu_shares == 0
        && host.cgroup_parent.is_empty()
        && host.block_io_weight == 0
        && host
            .block_io_weight_devices
            .as_ref()
            .is_none_or(BoundedVec::is_empty)
        && host
            .block_io_read_bps
            .as_ref()
            .is_none_or(BoundedVec::is_empty)
        && host
            .block_io_write_bps
            .as_ref()
            .is_none_or(BoundedVec::is_empty)
        && host
            .block_io_read_iops
            .as_ref()
            .is_none_or(BoundedVec::is_empty)
        && host
            .block_io_write_iops
            .as_ref()
            .is_none_or(BoundedVec::is_empty)
        && host.cpu_period == 0
        && host.cpu_quota == 0
        && host.cpu_realtime_period == 0
        && host.cpu_realtime_runtime == 0
        && host.cpuset_cpus.is_empty()
        && host.cpuset_mems.is_empty()
        && host.devices.is_empty()
        && host
            .device_cgroup_rules
            .as_ref()
            .is_none_or(BoundedVec::is_empty)
        && host
            .device_requests
            .as_ref()
            .is_none_or(BoundedVec::is_empty)
}

#[cfg(unix)]
fn exact_host_memory(host: &HostConfigResponse) -> bool {
    host.memory_bytes > 0
        && host.memory_reservation == 0
        && host.memory_swap == host.memory_bytes
        && host.memory_swappiness.is_none()
        // Docker v1.44 reports the requested `false` either directly while
        // created or normalized to null after start; `true` is never accepted.
        && host.oom_kill_disable.is_none_or(|disabled| !disabled)
        && host.pids_limit > 0
}

#[cfg(unix)]
fn exact_host_resource_surface(host: &HostConfigResponse) -> bool {
    host.ulimits.is_empty()
        && !host.init
        && host.log_config.driver == "none"
        && host.log_config.options.is_empty()
        && host.cpu_count == 0
        && host.cpu_percent == 0
        && host.io_maximum_iops == 0
        && host.io_maximum_bandwidth == 0
        && host
            .storage_options
            .as_ref()
            .is_none_or(BoundedMap::is_empty)
        && host.sysctls.as_ref().is_none_or(BoundedMap::is_empty)
}

#[cfg(unix)]
fn exact_host_paths(host: &HostConfigResponse) -> bool {
    host.masked_paths
        .as_slice()
        .iter()
        .map(String::as_str)
        .eq(MASKED_PATHS.iter().copied())
        && host
            .read_only_paths
            .as_slice()
            .iter()
            .map(String::as_str)
            .eq(READ_ONLY_PATHS.iter().copied())
}

#[cfg(unix)]
fn exact_network(network: &NetworkSettingsResponse) -> bool {
    network.sandbox_id.is_empty()
        && network.sandbox_key.is_empty()
        && network.ports.is_empty()
        && network.networks.is_empty()
        && network.bridge.as_ref().is_none_or(String::is_empty)
        && network.hairpin_mode.is_none_or(|enabled| !enabled)
        && network
            .link_local_ipv6_address
            .as_ref()
            .is_none_or(String::is_empty)
        && network
            .link_local_ipv6_prefix_length
            .is_none_or(|length| length == 0)
        && network
            .secondary_ip_addresses
            .as_ref()
            .is_none_or(BoundedVec::is_empty)
        && network
            .secondary_ipv6_addresses
            .as_ref()
            .is_none_or(BoundedVec::is_empty)
        && network.endpoint_id.as_ref().is_none_or(String::is_empty)
        && network.gateway.as_ref().is_none_or(String::is_empty)
        && network
            .global_ipv6_address
            .as_ref()
            .is_none_or(String::is_empty)
        && network
            .global_ipv6_prefix_length
            .is_none_or(|length| length == 0)
        && network.ip_address.as_ref().is_none_or(String::is_empty)
        && network.ip_prefix_length.is_none_or(|length| length == 0)
        && network.ipv6_gateway.as_ref().is_none_or(String::is_empty)
        && network.mac_address.as_ref().is_none_or(String::is_empty)
}

#[cfg(unix)]
fn valid_neutral_environment(environment: &[String]) -> bool {
    let mut previous: Option<&str> = None;
    environment.iter().all(|entry| {
        let Some((name, value)) = entry.split_once('=') else {
            return false;
        };
        let canonical = value.is_empty()
            && valid_environment_name(name)
            && previous.is_none_or(|previous| previous < name);
        previous = Some(name);
        canonical
    })
}

#[cfg(unix)]
fn decode_multiplexed(
    bytes: &[u8],
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<(Vec<u8>, Vec<u8>), EngineApiError> {
    let mut remaining = bytes;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    while !remaining.is_empty() {
        let header = remaining.get(..8).ok_or(EngineApiError::InvalidResponse)?;
        if header[1..4] != [0, 0, 0] {
            return Err(EngineApiError::InvalidResponse);
        }
        let length = usize::try_from(u32::from_be_bytes(
            header[4..8]
                .try_into()
                .map_err(|_| EngineApiError::InvalidResponse)?,
        ))
        .map_err(|_| EngineApiError::InvalidResponse)?;
        let payload = remaining
            .get(8..8 + length)
            .ok_or(EngineApiError::InvalidResponse)?;
        let (target, limit) = match header[0] {
            1 => (&mut stdout, stdout_limit),
            2 => (&mut stderr, stderr_limit),
            _ => return Err(EngineApiError::InvalidResponse),
        };
        if target
            .len()
            .checked_add(payload.len())
            .is_none_or(|length| length > limit)
        {
            return Err(EngineApiError::OutputLimit);
        }
        target.extend_from_slice(payload);
        remaining = &remaining[8 + length..];
    }
    Ok((stdout, stderr))
}

#[cfg(unix)]
impl ContainerCreateRequest<'_> {
    fn new(definition: &ContainerDefinition) -> ContainerCreateRequest<'_> {
        ContainerCreateRequest {
            hostname: "",
            domain_name: "",
            user: &definition.user,
            attach_stdin: false,
            attach_stdout: false,
            attach_stderr: false,
            tty: false,
            open_stdin: false,
            stdin_once: false,
            args_escaped: false,
            environment: &definition.environment,
            command: &definition.arguments,
            healthcheck: HealthcheckRequest::disabled(),
            image: &definition.image,
            exposed_ports: BTreeMap::new(),
            volumes: BTreeMap::new(),
            working_directory: &definition.working_directory,
            entrypoint: [&definition.entrypoint],
            network_disabled: true,
            labels: &definition.labels,
            on_build: Vec::new(),
            shell: Vec::new(),
            stop_signal: "SIGKILL",
            stop_timeout: 0,
            mac_address: "",
            host_config: HostConfigRequest::new(definition),
            networking_config: NetworkingConfigRequest {
                endpoints: BTreeMap::new(),
            },
        }
    }
}

#[cfg(unix)]
impl<'a> HostConfigRequest<'a> {
    fn new(definition: &'a ContainerDefinition) -> Self {
        Self {
            binds: Vec::new(),
            container_id_file: "",
            log_config: LogConfigRequest {
                driver: "none",
                options: BTreeMap::new(),
            },
            network_mode: "none",
            port_bindings: BTreeMap::new(),
            restart_policy: RestartPolicyRequest {
                name: "no",
                maximum_retry_count: 0,
            },
            auto_remove: false,
            volume_driver: "",
            volumes_from: Vec::new(),
            cap_add: Vec::new(),
            cap_drop: ["ALL"],
            cgroup_namespace_mode: "private",
            dns: Vec::new(),
            dns_options: Vec::new(),
            dns_search: Vec::new(),
            extra_hosts: Vec::new(),
            group_add: Vec::new(),
            ipc_mode: "private",
            cgroup: "",
            links: Vec::new(),
            oom_score_adjustment: 0,
            pid_mode: "",
            privileged: false,
            publish_all_ports: false,
            read_only_root: definition.read_only_root,
            security_options: ["no-new-privileges=true", "seccomp=builtin"],
            uts_mode: "",
            user_namespace_mode: "",
            runtime: "runc",
            isolation: "",
            shm_bytes: SHM_BYTES,
            console_size: [0, 0],
            cpu_shares: 0,
            cgroup_parent: "",
            block_io_weight: 0,
            block_io_weight_devices: Vec::new(),
            block_io_read_bps: Vec::new(),
            block_io_write_bps: Vec::new(),
            block_io_read_iops: Vec::new(),
            block_io_write_iops: Vec::new(),
            cpu_period: 0,
            cpu_quota: 0,
            cpu_realtime_period: 0,
            cpu_realtime_runtime: 0,
            cpuset_cpus: "",
            cpuset_mems: "",
            memory_bytes: definition.memory_bytes,
            memory_reservation: 0,
            memory_swap: definition.memory_bytes,
            memory_swappiness: None,
            nano_cpus: definition.nano_cpus,
            oom_kill_disable: false,
            pids_limit: definition.pids_limit,
            ulimits: Vec::new(),
            devices: Vec::new(),
            device_cgroup_rules: Vec::new(),
            device_requests: Vec::new(),
            mounts: Vec::new(),
            tmpfs: &definition.tmpfs,
            init: false,
            cpu_count: 0,
            cpu_percent: 0,
            io_maximum_iops: 0,
            io_maximum_bandwidth: 0,
            storage_options: BTreeMap::new(),
            sysctls: BTreeMap::new(),
            masked_paths: MASKED_PATHS,
            read_only_paths: READ_ONLY_PATHS,
        }
    }
}

#[cfg(unix)]
#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ContainerCreateRequest<'a> {
    #[serde(rename = "Hostname")]
    hostname: &'static str,
    #[serde(rename = "Domainname")]
    domain_name: &'static str,
    #[serde(rename = "User")]
    user: &'a str,
    #[serde(rename = "AttachStdin")]
    attach_stdin: bool,
    #[serde(rename = "AttachStdout")]
    attach_stdout: bool,
    #[serde(rename = "AttachStderr")]
    attach_stderr: bool,
    #[serde(rename = "Tty")]
    tty: bool,
    #[serde(rename = "OpenStdin")]
    open_stdin: bool,
    #[serde(rename = "StdinOnce")]
    stdin_once: bool,
    #[serde(rename = "ArgsEscaped")]
    args_escaped: bool,
    #[serde(rename = "Env")]
    environment: &'a [String],
    #[serde(rename = "Cmd")]
    command: &'a [String],
    #[serde(rename = "Healthcheck")]
    healthcheck: HealthcheckRequest,
    #[serde(rename = "Image")]
    image: &'a str,
    #[serde(rename = "ExposedPorts")]
    exposed_ports: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(rename = "Volumes")]
    volumes: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(rename = "WorkingDir")]
    working_directory: &'a str,
    #[serde(rename = "Entrypoint")]
    entrypoint: [&'a String; 1],
    #[serde(rename = "NetworkDisabled")]
    network_disabled: bool,
    #[serde(rename = "Labels")]
    labels: &'a BTreeMap<String, String>,
    #[serde(rename = "OnBuild")]
    on_build: Vec<String>,
    #[serde(rename = "Shell")]
    shell: Vec<String>,
    #[serde(rename = "StopSignal")]
    stop_signal: &'static str,
    #[serde(rename = "StopTimeout")]
    stop_timeout: i64,
    #[serde(rename = "MacAddress")]
    mac_address: &'static str,
    #[serde(rename = "HostConfig")]
    host_config: HostConfigRequest<'a>,
    #[serde(rename = "NetworkingConfig")]
    networking_config: NetworkingConfigRequest,
}

#[cfg(unix)]
#[derive(Serialize)]
struct HealthcheckRequest {
    #[serde(rename = "Test")]
    test: [&'static str; 1],
    #[serde(rename = "Interval")]
    interval: i64,
    #[serde(rename = "Timeout")]
    timeout: i64,
    #[serde(rename = "Retries")]
    retries: i64,
    #[serde(rename = "StartPeriod")]
    start_period: i64,
    #[serde(rename = "StartInterval")]
    start_interval: i64,
}

#[cfg(unix)]
impl HealthcheckRequest {
    const fn disabled() -> Self {
        Self {
            test: ["NONE"],
            interval: 0,
            timeout: 0,
            retries: 0,
            start_period: 0,
            start_interval: 0,
        }
    }
}

#[cfg(unix)]
#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct HostConfigRequest<'a> {
    #[serde(rename = "Binds")]
    binds: Vec<String>,
    #[serde(rename = "ContainerIDFile")]
    container_id_file: &'static str,
    #[serde(rename = "LogConfig")]
    log_config: LogConfigRequest,
    #[serde(rename = "NetworkMode")]
    network_mode: &'static str,
    #[serde(rename = "PortBindings")]
    port_bindings: BTreeMap<String, String>,
    #[serde(rename = "RestartPolicy")]
    restart_policy: RestartPolicyRequest,
    #[serde(rename = "AutoRemove")]
    auto_remove: bool,
    #[serde(rename = "VolumeDriver")]
    volume_driver: &'static str,
    #[serde(rename = "VolumesFrom")]
    volumes_from: Vec<String>,
    #[serde(rename = "CapAdd")]
    cap_add: Vec<String>,
    #[serde(rename = "CapDrop")]
    cap_drop: [&'static str; 1],
    #[serde(rename = "CgroupnsMode")]
    cgroup_namespace_mode: &'static str,
    #[serde(rename = "Dns")]
    dns: Vec<String>,
    #[serde(rename = "DnsOptions")]
    dns_options: Vec<String>,
    #[serde(rename = "DnsSearch")]
    dns_search: Vec<String>,
    #[serde(rename = "ExtraHosts")]
    extra_hosts: Vec<String>,
    #[serde(rename = "GroupAdd")]
    group_add: Vec<String>,
    #[serde(rename = "IpcMode")]
    ipc_mode: &'static str,
    #[serde(rename = "Cgroup")]
    cgroup: &'static str,
    #[serde(rename = "Links")]
    links: Vec<String>,
    #[serde(rename = "OomScoreAdj")]
    oom_score_adjustment: i64,
    #[serde(rename = "PidMode")]
    pid_mode: &'static str,
    #[serde(rename = "Privileged")]
    privileged: bool,
    #[serde(rename = "PublishAllPorts")]
    publish_all_ports: bool,
    #[serde(rename = "ReadonlyRootfs")]
    read_only_root: bool,
    #[serde(rename = "SecurityOpt")]
    security_options: [&'static str; 2],
    #[serde(rename = "UTSMode")]
    uts_mode: &'static str,
    #[serde(rename = "UsernsMode")]
    user_namespace_mode: &'static str,
    #[serde(rename = "Runtime")]
    runtime: &'static str,
    #[serde(rename = "Isolation")]
    isolation: &'static str,
    #[serde(rename = "ShmSize")]
    shm_bytes: i64,
    #[serde(rename = "ConsoleSize")]
    console_size: [u64; 2],
    #[serde(rename = "CpuShares")]
    cpu_shares: i64,
    #[serde(rename = "CgroupParent")]
    cgroup_parent: &'static str,
    #[serde(rename = "BlkioWeight")]
    block_io_weight: u16,
    #[serde(rename = "BlkioWeightDevice")]
    block_io_weight_devices: Vec<BTreeMap<String, String>>,
    #[serde(rename = "BlkioDeviceReadBps")]
    block_io_read_bps: Vec<BTreeMap<String, String>>,
    #[serde(rename = "BlkioDeviceWriteBps")]
    block_io_write_bps: Vec<BTreeMap<String, String>>,
    #[serde(rename = "BlkioDeviceReadIOps")]
    block_io_read_iops: Vec<BTreeMap<String, String>>,
    #[serde(rename = "BlkioDeviceWriteIOps")]
    block_io_write_iops: Vec<BTreeMap<String, String>>,
    #[serde(rename = "CpuPeriod")]
    cpu_period: i64,
    #[serde(rename = "CpuQuota")]
    cpu_quota: i64,
    #[serde(rename = "CpuRealtimePeriod")]
    cpu_realtime_period: i64,
    #[serde(rename = "CpuRealtimeRuntime")]
    cpu_realtime_runtime: i64,
    #[serde(rename = "CpusetCpus")]
    cpuset_cpus: &'static str,
    #[serde(rename = "CpusetMems")]
    cpuset_mems: &'static str,
    #[serde(rename = "Memory")]
    memory_bytes: i64,
    #[serde(rename = "MemoryReservation")]
    memory_reservation: i64,
    #[serde(rename = "MemorySwap")]
    memory_swap: i64,
    #[serde(rename = "MemorySwappiness")]
    memory_swappiness: Option<i64>,
    #[serde(rename = "NanoCpus")]
    nano_cpus: i64,
    #[serde(rename = "OomKillDisable")]
    oom_kill_disable: bool,
    #[serde(rename = "PidsLimit")]
    pids_limit: i64,
    #[serde(rename = "Ulimits")]
    ulimits: Vec<String>,
    #[serde(rename = "Devices")]
    devices: Vec<String>,
    #[serde(rename = "DeviceCgroupRules")]
    device_cgroup_rules: Vec<String>,
    #[serde(rename = "DeviceRequests")]
    device_requests: Vec<String>,
    #[serde(rename = "Mounts")]
    mounts: Vec<BTreeMap<String, String>>,
    #[serde(rename = "Tmpfs")]
    tmpfs: &'a BTreeMap<String, String>,
    #[serde(rename = "Init")]
    init: bool,
    #[serde(rename = "CpuCount")]
    cpu_count: i64,
    #[serde(rename = "CpuPercent")]
    cpu_percent: i64,
    #[serde(rename = "IOMaximumIOps")]
    io_maximum_iops: u64,
    #[serde(rename = "IOMaximumBandwidth")]
    io_maximum_bandwidth: u64,
    #[serde(rename = "StorageOpt")]
    storage_options: BTreeMap<String, String>,
    #[serde(rename = "Sysctls")]
    sysctls: BTreeMap<String, String>,
    #[serde(rename = "MaskedPaths")]
    masked_paths: &'static [&'static str],
    #[serde(rename = "ReadonlyPaths")]
    read_only_paths: &'static [&'static str],
}

#[cfg(unix)]
#[derive(Serialize)]
struct LogConfigRequest {
    #[serde(rename = "Type")]
    driver: &'static str,
    #[serde(rename = "Config")]
    options: BTreeMap<String, String>,
}

#[cfg(unix)]
#[derive(Serialize)]
struct RestartPolicyRequest {
    #[serde(rename = "Name")]
    name: &'static str,
    #[serde(rename = "MaximumRetryCount")]
    maximum_retry_count: u64,
}

#[cfg(unix)]
#[derive(Serialize)]
struct NetworkingConfigRequest {
    #[serde(rename = "EndpointsConfig")]
    endpoints: BTreeMap<String, String>,
}

#[cfg(unix)]
#[derive(Deserialize)]
struct ContainerCreateResponse {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Warnings")]
    warnings: Option<BoundedVec<String, 16>>,
}

#[cfg(unix)]
#[derive(Deserialize)]
struct ImageResponse {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "RepoDigests")]
    repo_digests: BoundedVec<String, MAX_REPO_DIGESTS>,
    #[serde(rename = "Os")]
    operating_system: String,
    #[serde(rename = "Architecture")]
    architecture: String,
    #[serde(rename = "Config")]
    config: ImageConfigResponse,
}

#[cfg(unix)]
#[derive(Deserialize)]
struct ImageConfigResponse {
    #[serde(rename = "Env")]
    environment: Option<BoundedVec<String, MAX_ENVIRONMENT>>,
    #[serde(rename = "Volumes")]
    volumes: Option<BoundedMap<String, IgnoredAny, MAX_DECLARED_VOLUMES>>,
    #[serde(rename = "ExposedPorts")]
    exposed_ports: Option<BoundedMap<String, IgnoredAny, 64>>,
    #[serde(rename = "Healthcheck")]
    healthcheck: Option<ImageHealthcheckResponse>,
    #[serde(rename = "Labels")]
    labels: Option<BoundedMap<String, String, MAX_LABELS>>,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageHealthcheckResponse {
    #[serde(rename = "Test")]
    _test: Option<BoundedVec<String, 8>>,
    #[serde(rename = "Interval")]
    _interval: Option<i64>,
    #[serde(rename = "Timeout")]
    _timeout: Option<i64>,
    #[serde(rename = "Retries")]
    _retries: Option<i64>,
    #[serde(rename = "StartPeriod")]
    _start_period: Option<i64>,
    #[serde(rename = "StartInterval")]
    _start_interval: Option<i64>,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContainerResponse {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Image")]
    image_id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Created")]
    _created: IgnoredAny,
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Args")]
    arguments: BoundedVec<String, MAX_ARGUMENTS>,
    #[serde(rename = "ResolvConfPath")]
    _resolv_conf_path: String,
    #[serde(rename = "HostnamePath")]
    _hostname_path: String,
    #[serde(rename = "HostsPath")]
    _hosts_path: String,
    #[serde(rename = "LogPath")]
    log_path: String,
    #[serde(rename = "RestartCount")]
    restart_count: i64,
    #[serde(rename = "Driver")]
    driver: String,
    #[serde(rename = "Platform")]
    platform: String,
    #[serde(rename = "MountLabel")]
    mount_label: String,
    #[serde(rename = "ProcessLabel")]
    process_label: String,
    #[serde(rename = "AppArmorProfile")]
    app_armor_profile: String,
    #[serde(rename = "ExecIDs")]
    exec_ids: Option<BoundedVec<String, 16>>,
    #[serde(rename = "State")]
    state: ContainerStateResponse,
    #[serde(rename = "Config")]
    config: ContainerConfigResponse,
    #[serde(rename = "HostConfig")]
    host_config: HostConfigResponse,
    #[serde(rename = "Mounts")]
    mounts: BoundedVec<IgnoredAny, MAX_MOUNTS>,
    #[serde(rename = "NetworkSettings")]
    network_settings: NetworkSettingsResponse,
    #[serde(rename = "GraphDriver")]
    _graph_driver: IgnoredAny,
}

/// Minimal identity surface used only to prove custody before cleanup.
///
/// This intentionally ignores executable/runtime fields: Docker must remain
/// able to remove an owned container after daemon normalization, image loss,
/// or a dead runtime makes the stricter execution parser reject it.
#[cfg(unix)]
#[derive(Deserialize)]
struct ContainerCustodyResponse {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Image")]
    image_id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "State")]
    state: ContainerCustodyStateResponse,
    #[serde(rename = "Config")]
    config: ContainerCustodyConfigResponse,
}

#[cfg(unix)]
#[derive(Deserialize)]
struct ContainerCustodyStateResponse {
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "ExitCode")]
    exit_code: i64,
}

#[cfg(unix)]
#[derive(Deserialize)]
struct ContainerCustodyConfigResponse {
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Labels")]
    labels: Option<BoundedMap<String, String, MAX_LABELS>>,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct ContainerStateResponse {
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "Paused")]
    paused: bool,
    #[serde(rename = "Restarting")]
    restarting: bool,
    #[serde(rename = "OOMKilled")]
    out_of_memory: bool,
    #[serde(rename = "Dead")]
    dead: bool,
    #[serde(rename = "Pid")]
    pid: i64,
    #[serde(rename = "ExitCode")]
    exit_code: i64,
    #[serde(rename = "Error")]
    error: String,
    #[serde(rename = "StartedAt")]
    _started_at: String,
    #[serde(rename = "FinishedAt")]
    _finished_at: String,
    #[serde(rename = "Health")]
    health: Option<IgnoredAny>,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct ContainerConfigResponse {
    #[serde(rename = "Hostname")]
    hostname: String,
    #[serde(rename = "Domainname")]
    domain_name: String,
    #[serde(rename = "User")]
    user: String,
    #[serde(rename = "AttachStdin")]
    attach_stdin: bool,
    #[serde(rename = "AttachStdout")]
    attach_stdout: bool,
    #[serde(rename = "AttachStderr")]
    attach_stderr: bool,
    #[serde(rename = "Tty")]
    tty: bool,
    #[serde(rename = "OpenStdin")]
    open_stdin: bool,
    #[serde(rename = "StdinOnce")]
    stdin_once: bool,
    #[serde(rename = "ArgsEscaped")]
    args_escaped: Option<bool>,
    #[serde(rename = "Env")]
    environment: BoundedVec<String, MAX_ENVIRONMENT>,
    #[serde(rename = "Cmd")]
    command: BoundedVec<String, MAX_ARGUMENTS>,
    #[serde(rename = "Healthcheck")]
    healthcheck: HealthcheckResponse,
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "ExposedPorts")]
    exposed_ports: Option<BoundedMap<String, IgnoredAny, 64>>,
    #[serde(rename = "Volumes")]
    volumes: Option<BoundedMap<String, IgnoredAny, MAX_DECLARED_VOLUMES>>,
    #[serde(rename = "WorkingDir")]
    working_directory: String,
    #[serde(rename = "Entrypoint")]
    entrypoint: BoundedVec<String, 4>,
    #[serde(rename = "NetworkDisabled")]
    network_disabled: bool,
    #[serde(rename = "Labels")]
    labels: BoundedMap<String, String, MAX_LABELS>,
    #[serde(rename = "OnBuild")]
    on_build: Option<BoundedVec<String, MAX_ARGUMENTS>>,
    #[serde(rename = "Shell")]
    shell: Option<BoundedVec<String, MAX_ARGUMENTS>>,
    #[serde(rename = "StopSignal")]
    stop_signal: String,
    #[serde(rename = "StopTimeout")]
    stop_timeout: Option<i64>,
    #[serde(rename = "MacAddress")]
    mac_address: Option<String>,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthcheckResponse {
    #[serde(rename = "Test")]
    test: BoundedVec<String, 8>,
    #[serde(rename = "Interval", default)]
    interval: i64,
    #[serde(rename = "Timeout", default)]
    timeout: i64,
    #[serde(rename = "Retries", default)]
    retries: i64,
    #[serde(rename = "StartPeriod", default)]
    start_period: i64,
    #[serde(rename = "StartInterval", default)]
    start_interval: i64,
}

#[cfg(unix)]
impl HealthcheckResponse {
    fn is_disabled(&self) -> bool {
        self.test.as_slice() == ["NONE"]
            && self.interval == 0
            && self.timeout == 0
            && self.retries == 0
            && self.start_period == 0
            && self.start_interval == 0
    }
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct HostConfigResponse {
    #[serde(rename = "Binds")]
    binds: Option<BoundedVec<String, MAX_MOUNTS>>,
    #[serde(rename = "ContainerIDFile")]
    container_id_file: String,
    #[serde(rename = "LogConfig")]
    log_config: LogConfigResponse,
    #[serde(rename = "NetworkMode")]
    network_mode: String,
    #[serde(rename = "PortBindings")]
    port_bindings: BoundedMap<String, IgnoredAny, 32>,
    #[serde(rename = "RestartPolicy")]
    restart_policy: RestartPolicyResponse,
    #[serde(rename = "AutoRemove")]
    auto_remove: bool,
    #[serde(rename = "VolumeDriver")]
    volume_driver: String,
    #[serde(rename = "VolumesFrom")]
    volumes_from: Option<BoundedVec<String, MAX_MOUNTS>>,
    #[serde(rename = "CapAdd")]
    cap_add: Option<BoundedVec<String, 64>>,
    #[serde(rename = "CapDrop")]
    cap_drop: BoundedVec<String, 64>,
    #[serde(rename = "CgroupnsMode")]
    cgroup_namespace_mode: String,
    #[serde(rename = "Dns")]
    dns: Option<BoundedVec<String, 16>>,
    #[serde(rename = "DnsOptions")]
    dns_options: BoundedVec<String, 16>,
    #[serde(rename = "DnsSearch")]
    dns_search: BoundedVec<String, 16>,
    #[serde(rename = "ExtraHosts")]
    extra_hosts: Option<BoundedVec<String, 64>>,
    #[serde(rename = "GroupAdd")]
    group_add: Option<BoundedVec<String, 64>>,
    #[serde(rename = "IpcMode")]
    ipc_mode: String,
    #[serde(rename = "Cgroup")]
    cgroup: String,
    #[serde(rename = "Links")]
    links: Option<BoundedVec<String, 64>>,
    #[serde(rename = "OomScoreAdj")]
    oom_score_adjustment: i64,
    #[serde(rename = "PidMode")]
    pid_mode: String,
    #[serde(rename = "Privileged")]
    privileged: bool,
    #[serde(rename = "PublishAllPorts")]
    publish_all_ports: bool,
    #[serde(rename = "ReadonlyRootfs")]
    read_only_root: bool,
    #[serde(rename = "SecurityOpt")]
    security_options: BoundedVec<String, MAX_SECURITY_OPTIONS>,
    #[serde(rename = "UTSMode")]
    uts_mode: String,
    #[serde(rename = "UsernsMode")]
    user_namespace_mode: String,
    #[serde(rename = "Runtime")]
    runtime: String,
    #[serde(rename = "Isolation")]
    isolation: String,
    #[serde(rename = "ShmSize")]
    shm_bytes: i64,
    #[serde(rename = "ConsoleSize")]
    console_size: [u64; 2],
    #[serde(rename = "CpuShares")]
    cpu_shares: i64,
    #[serde(rename = "CgroupParent")]
    cgroup_parent: String,
    #[serde(rename = "BlkioWeight")]
    block_io_weight: u16,
    #[serde(rename = "BlkioWeightDevice")]
    block_io_weight_devices: Option<BoundedVec<IgnoredAny, MAX_DEVICES>>,
    #[serde(rename = "BlkioDeviceReadBps")]
    block_io_read_bps: Option<BoundedVec<IgnoredAny, MAX_DEVICES>>,
    #[serde(rename = "BlkioDeviceWriteBps")]
    block_io_write_bps: Option<BoundedVec<IgnoredAny, MAX_DEVICES>>,
    #[serde(rename = "BlkioDeviceReadIOps")]
    block_io_read_iops: Option<BoundedVec<IgnoredAny, MAX_DEVICES>>,
    #[serde(rename = "BlkioDeviceWriteIOps")]
    block_io_write_iops: Option<BoundedVec<IgnoredAny, MAX_DEVICES>>,
    #[serde(rename = "CpuPeriod")]
    cpu_period: i64,
    #[serde(rename = "CpuQuota")]
    cpu_quota: i64,
    #[serde(rename = "CpuRealtimePeriod")]
    cpu_realtime_period: i64,
    #[serde(rename = "CpuRealtimeRuntime")]
    cpu_realtime_runtime: i64,
    #[serde(rename = "CpusetCpus")]
    cpuset_cpus: String,
    #[serde(rename = "CpusetMems")]
    cpuset_mems: String,
    #[serde(rename = "Memory")]
    memory_bytes: i64,
    #[serde(rename = "MemoryReservation")]
    memory_reservation: i64,
    #[serde(rename = "MemorySwap")]
    memory_swap: i64,
    #[serde(rename = "MemorySwappiness")]
    memory_swappiness: Option<i64>,
    #[serde(rename = "NanoCpus")]
    nano_cpus: i64,
    #[serde(rename = "OomKillDisable")]
    oom_kill_disable: Option<bool>,
    #[serde(rename = "PidsLimit")]
    pids_limit: i64,
    #[serde(rename = "Ulimits")]
    ulimits: BoundedVec<IgnoredAny, 64>,
    #[serde(rename = "Devices")]
    devices: BoundedVec<IgnoredAny, MAX_DEVICES>,
    #[serde(rename = "DeviceCgroupRules")]
    device_cgroup_rules: Option<BoundedVec<String, MAX_DEVICES>>,
    #[serde(rename = "DeviceRequests")]
    device_requests: Option<BoundedVec<IgnoredAny, MAX_DEVICES>>,
    #[serde(rename = "Mounts")]
    mounts: Option<BoundedVec<IgnoredAny, MAX_MOUNTS>>,
    #[serde(rename = "Tmpfs")]
    tmpfs: Option<BoundedMap<String, String, MAX_MOUNTS>>,
    #[serde(rename = "Init")]
    init: bool,
    #[serde(rename = "CpuCount")]
    cpu_count: i64,
    #[serde(rename = "CpuPercent")]
    cpu_percent: i64,
    #[serde(rename = "IOMaximumIOps")]
    io_maximum_iops: u64,
    #[serde(rename = "IOMaximumBandwidth")]
    io_maximum_bandwidth: u64,
    #[serde(rename = "StorageOpt")]
    storage_options: Option<BoundedMap<String, String, 32>>,
    #[serde(rename = "Sysctls")]
    sysctls: Option<BoundedMap<String, String, 64>>,
    #[serde(rename = "MaskedPaths")]
    masked_paths: BoundedVec<String, 64>,
    #[serde(rename = "ReadonlyPaths")]
    read_only_paths: BoundedVec<String, 64>,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogConfigResponse {
    #[serde(rename = "Type")]
    driver: String,
    #[serde(rename = "Config")]
    options: BoundedMap<String, String, 16>,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartPolicyResponse {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "MaximumRetryCount")]
    maximum_retry_count: u64,
}

#[cfg(unix)]
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkSettingsResponse {
    #[serde(rename = "Bridge")]
    bridge: Option<String>,
    #[serde(rename = "HairpinMode")]
    hairpin_mode: Option<bool>,
    #[serde(rename = "LinkLocalIPv6Address")]
    link_local_ipv6_address: Option<String>,
    #[serde(rename = "LinkLocalIPv6PrefixLen")]
    link_local_ipv6_prefix_length: Option<i64>,
    #[serde(rename = "SandboxID")]
    sandbox_id: String,
    #[serde(rename = "SandboxKey")]
    sandbox_key: String,
    #[serde(rename = "SecondaryIPAddresses")]
    secondary_ip_addresses: Option<BoundedVec<IgnoredAny, 64>>,
    #[serde(rename = "SecondaryIPv6Addresses")]
    secondary_ipv6_addresses: Option<BoundedVec<IgnoredAny, 64>>,
    #[serde(rename = "EndpointID")]
    endpoint_id: Option<String>,
    #[serde(rename = "Gateway")]
    gateway: Option<String>,
    #[serde(rename = "GlobalIPv6Address")]
    global_ipv6_address: Option<String>,
    #[serde(rename = "GlobalIPv6PrefixLen")]
    global_ipv6_prefix_length: Option<i64>,
    #[serde(rename = "IPAddress")]
    ip_address: Option<String>,
    #[serde(rename = "IPPrefixLen")]
    ip_prefix_length: Option<i64>,
    #[serde(rename = "IPv6Gateway")]
    ipv6_gateway: Option<String>,
    #[serde(rename = "MacAddress")]
    mac_address: Option<String>,
    #[serde(rename = "Ports")]
    ports: BoundedMap<String, IgnoredAny, 64>,
    #[serde(rename = "Networks")]
    networks: BoundedMap<String, IgnoredAny, MAX_NETWORKS>,
}

#[cfg(unix)]
#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ExecCreateRequest<'a> {
    #[serde(rename = "AttachStdin")]
    attach_stdin: bool,
    #[serde(rename = "AttachStdout")]
    attach_stdout: bool,
    #[serde(rename = "AttachStderr")]
    attach_stderr: bool,
    #[serde(rename = "Tty")]
    tty: bool,
    #[serde(rename = "Env")]
    environment: Vec<String>,
    #[serde(rename = "Cmd")]
    command: Vec<String>,
    #[serde(rename = "Privileged")]
    privileged: bool,
    #[serde(rename = "User")]
    user: &'a str,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecCreateResponse {
    #[serde(rename = "Id")]
    id: String,
}

#[cfg(unix)]
#[derive(Serialize)]
struct ExecStartRequest {
    #[serde(rename = "Detach")]
    detach: bool,
    #[serde(rename = "Tty")]
    tty: bool,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct ExecInspectResponse {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "ExitCode")]
    exit_code: Option<i64>,
    #[serde(rename = "ProcessConfig")]
    process_config: ExecProcessConfigResponse,
    #[serde(rename = "OpenStdin")]
    open_stdin: bool,
    #[serde(rename = "OpenStderr")]
    open_stderr: bool,
    #[serde(rename = "OpenStdout")]
    open_stdout: bool,
    #[serde(rename = "CanRemove")]
    can_remove: bool,
    #[serde(rename = "ContainerID")]
    container_id: String,
    #[serde(rename = "DetachKeys")]
    detach_keys: String,
    #[serde(rename = "Pid")]
    pid: i64,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecProcessConfigResponse {
    tty: bool,
    entrypoint: String,
    arguments: BoundedVec<String, MAX_ARGUMENTS>,
    privileged: bool,
    user: String,
}

#[cfg(unix)]
impl ExecInspectResponse {
    fn matches_common(&self, id: &str, container_id: &str, command: &[String], user: &str) -> bool {
        let Some((entrypoint, arguments)) = command.split_first() else {
            return false;
        };
        self.id == id
            && self.container_id == container_id
            && !self.process_config.tty
            && self.process_config.entrypoint == *entrypoint
            && self.process_config.arguments.as_slice() == arguments
            && !self.process_config.privileged
            && self.process_config.user == user
            && self.open_stdin
            && self.open_stderr
            && self.open_stdout
            && !self.can_remove
            && self.detach_keys.is_empty()
    }

    fn matches_created(
        &self,
        id: &str,
        container_id: &str,
        command: &[String],
        user: &str,
    ) -> bool {
        self.matches_common(id, container_id, command, user)
            && !self.running
            && self.exit_code.is_none()
            && self.pid == 0
    }

    fn matches_finished(&self, prepared: &PreparedEngineExec, request: &EngineExecRequest) -> bool {
        self.matches_common(
            &prepared.id,
            &request.container_id,
            &request.command,
            &request.user,
        ) && !self.running
            && self.exit_code.is_some()
            // Docker v1.44 retains the positive host PID after the exec has
            // stopped; the created form above is the only accepted zero PID.
            && self.pid > 0
    }
}

#[derive(Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Exact independent Docker v1.44 capability fields.
struct InfoResponse {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "ServerVersion")]
    server_version: String,
    #[serde(rename = "Architecture")]
    architecture: String,
    #[serde(rename = "OSType")]
    operating_system: String,
    #[serde(rename = "SecurityOptions")]
    security_options: Option<BoundedVec<String, MAX_SECURITY_OPTIONS>>,
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
}

#[derive(Deserialize)]
struct VersionResponse {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "ApiVersion")]
    api_version: String,
    #[serde(rename = "MinAPIVersion")]
    minimum_api_version: String,
    #[serde(rename = "Arch")]
    architecture: String,
    #[serde(rename = "Os")]
    operating_system: String,
}

#[derive(Deserialize)]
struct VolumeResponse {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Driver")]
    driver: String,
    #[serde(rename = "Scope")]
    scope: String,
    #[serde(rename = "Options")]
    options: Option<BoundedMap<String, String, MAX_VOLUME_OPTIONS>>,
    #[serde(rename = "Labels")]
    labels: Option<BoundedMap<String, String, MAX_LABELS>>,
}

#[derive(Deserialize)]
struct ContainerSummary {
    #[serde(rename = "Id")]
    id: String,
}
