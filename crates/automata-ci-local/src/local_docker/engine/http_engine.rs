use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    path::Path,
    str::FromStr as _,
    time::Duration,
};

use async_trait::async_trait;
use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use serde::de::IgnoredAny;

use super::{
    ContainerDefinition, ContainerNetworkAttachment, CreateNetwork, EngineContainerState,
    EngineExecOutput, EngineExecRequest, InspectedContainer, InspectedContainerCustody,
    InspectedImage, InspectedNetwork, Ipv4Network, LOCAL_DOCKER_GUEST_ARCHIVE_BYTES,
    LOCAL_DOCKER_GUEST_IMAGE_BINARY, LOCAL_DOCKER_SANDBOX_GUEST_BINARY, NetworkEndpoint,
    PreparedEngineExec, SandboxEngineApi,
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
const NETWORK_BYTES: usize = 512 * 1024;
#[cfg(unix)]
const EXEC_BYTES: usize = 128 * 1024;
#[cfg(unix)]
const MAX_REPO_DIGESTS: usize = 128;
#[cfg(unix)]
const MAX_REPO_TAGS: usize = 128;
#[cfg(unix)]
const MAX_DECLARED_VOLUMES: usize = 64;
#[cfg(unix)]
const MAX_MOUNTS: usize = 16;
#[cfg(unix)]
const MAX_ENVIRONMENT: usize = 256;
#[cfg(unix)]
const DEFAULT_CONTAINER_PATH: &str =
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
#[cfg(unix)]
const DOCKER_STREAM_HEADER_BYTES: usize = 8;
#[cfg(unix)]
const MAX_ARGUMENTS: usize = 256;
#[cfg(unix)]
const MAX_NETWORKS: usize = 8;
#[cfg(unix)]
const MAX_NETWORK_CONTAINERS: usize = 1_024;
#[cfg(unix)]
const MAX_NETWORK_IPAM_CONFIGS: usize = 4;
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

    async fn results_target_running(&self, id: &str) -> Result<bool, EngineApiError> {
        require_object_id(id)?;
        let path = format!("/containers/{}/json?size=false", encode_path_component(id));
        let container: Option<ResultsTargetResponse> = deadline(
            REQUEST_TIMEOUT,
            self.transport.optional_json(&path, CONTAINER_BYTES),
        )
        .await
        .map_err(map_transport)?;
        Ok(container.is_some_and(|container| {
            container.id == id && running_results_target(&container.state)
        }))
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

    async fn inspect_network(
        &self,
        id_or_name: &str,
    ) -> Result<Option<InspectedNetwork>, EngineApiError> {
        let path = format!(
            "/networks/{}?verbose=false&scope=local",
            encode_path_component(id_or_name)
        );
        let network: Option<NetworkResponse> = deadline(
            REQUEST_TIMEOUT,
            self.transport.optional_json(&path, NETWORK_BYTES),
        )
        .await
        .map_err(map_transport)?;
        network.map(normalize_network).transpose()
    }

    async fn create_network(&self, request: CreateNetwork) -> Result<String, EngineApiError> {
        let body = NetworkCreateRequest::new(&request)?;
        let created: NetworkCreateResponse = deadline(
            REQUEST_TIMEOUT,
            self.transport.json(
                Method::POST,
                "/networks/create",
                Some(&body),
                StatusCode::CREATED,
                EXEC_BYTES,
            ),
        )
        .await
        .map_err(map_transport)?;
        if !valid_object_id(&created.id) || !created.warning.is_empty() {
            return Err(EngineApiError::InvalidResponse);
        }
        Ok(created.id)
    }

    async fn remove_network(&self, id: &str) -> Result<(), EngineApiError> {
        require_object_id(id)?;
        let path = format!("/networks/{}", encode_path_component(id));
        deadline(
            REQUEST_TIMEOUT,
            self.transport
                .empty_or_not_found(Method::DELETE, &path, StatusCode::NO_CONTENT),
        )
        .await
        .map_err(map_transport)
    }

    async fn container_logs(&self, id: &str, byte_limit: usize) -> Result<Vec<u8>, EngineApiError> {
        require_object_id(id)?;
        if byte_limit == 0 || byte_limit > 64 * 1024 {
            return Err(EngineApiError::OutputLimit);
        }
        let raw_limit = byte_limit
            .checked_add(DOCKER_STREAM_HEADER_BYTES)
            .ok_or(EngineApiError::OutputLimit)?;
        let path = format!(
            "/containers/{}/logs?follow=false&stdout=true&stderr=true&since=0&timestamps=false&tail=all",
            encode_path_component(id)
        );
        let bytes = deadline(
            REQUEST_TIMEOUT,
            self.transport
                .bytes(&path, "application/vnd.docker.raw-stream", raw_limit),
        )
        .await
        .map_err(map_transport)?;
        let (stdout, stderr) = decode_multiplexed(&bytes, byte_limit, 1)?;
        if stderr.is_empty() {
            Ok(stdout)
        } else {
            Err(EngineApiError::InvalidResponse)
        }
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
    let config = response.config;
    let mut repo_tags = response.repo_tags.into_inner();
    repo_tags.sort();
    let mut repo_digests = response.repo_digests.into_inner();
    repo_digests.sort();
    if repo_tags.iter().any(String::is_empty) || repo_digests.iter().any(String::is_empty) {
        return Err(EngineApiError::InvalidResponse);
    }
    let mut declared_volumes = config.volumes.map_or_else(Vec::new, |volumes| {
        volumes.into_inner().into_keys().collect()
    });
    declared_volumes.sort();
    let mut declared_exposed_ports = config
        .exposed_ports
        .map_or_else(Vec::new, |ports| ports.into_inner().into_keys().collect());
    declared_exposed_ports.sort();
    let environment = config
        .environment
        .map_or_else(Vec::new, BoundedVec::into_inner);
    let default_path_only = environment.as_slice() == [DEFAULT_CONTAINER_PATH];
    let mut environment_names = environment
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
        repo_tags,
        repo_digests,
        operating_system: response.operating_system,
        architecture: response.architecture,
        declared_volumes,
        declared_exposed_ports,
        has_healthcheck: config.healthcheck.is_some(),
        labels: config
            .labels
            .map_or_else(BTreeMap::new, BoundedMap::into_inner),
        environment_names,
        default_path_only,
        user: config.user,
        entrypoint: config
            .entrypoint
            .map_or_else(Vec::new, BoundedVec::into_inner),
        command: config.command.map_or_else(Vec::new, BoundedVec::into_inner),
        working_directory: config.working_directory,
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
fn normalize_network(response: NetworkResponse) -> Result<InspectedNetwork, EngineApiError> {
    require_object_id(&response.id)?;
    if response.name.is_empty()
        || response.name.len() > 255
        || response.created.is_empty()
        || response.ipam.config.len() != 1
    {
        return Err(EngineApiError::InvalidResponse);
    }
    let configuration = response
        .ipam
        .config
        .into_inner()
        .into_iter()
        .next()
        .ok_or(EngineApiError::InvalidResponse)?;
    if configuration
        .ip_range
        .as_ref()
        .is_some_and(|value| !value.is_empty())
        || configuration
            .auxiliary_addresses
            .as_ref()
            .is_some_and(|values| !values.is_empty())
    {
        return Err(EngineApiError::InvalidResponse);
    }
    let ipv4_network = parse_ipv4_network(&configuration.subnet)?;
    let ipv4_gateway = parse_canonical_ipv4_address(
        configuration
            .gateway
            .as_deref()
            .ok_or(EngineApiError::InvalidResponse)?,
    )?;
    if !ipv4_network.usable(ipv4_gateway) {
        return Err(EngineApiError::InvalidResponse);
    }
    let containers = response
        .containers
        .map_or_else(BTreeMap::new, BoundedMap::into_inner)
        .into_iter()
        .map(|(id, endpoint)| normalize_network_endpoint(id, endpoint))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let unique_addresses = containers
        .values()
        .map(|endpoint| endpoint.ipv4_address)
        .collect::<BTreeSet<_>>();
    if unique_addresses.len() != containers.len()
        || unique_addresses.contains(&ipv4_gateway)
        || containers.values().any(|endpoint| {
            endpoint.ipv4_prefix != ipv4_network.prefix
                || !ipv4_network.usable(endpoint.ipv4_address)
        })
    {
        return Err(EngineApiError::InvalidResponse);
    }
    Ok(InspectedNetwork {
        id: response.id,
        name: response.name,
        driver: response.driver,
        scope: response.scope,
        enable_ipv4: response.enable_ipv4,
        enable_ipv6: response.enable_ipv6,
        internal: response.internal,
        attachable: response.attachable,
        ingress: response.ingress,
        config_only: response.config_only,
        config_from: response.config_from.network,
        ipam_driver: response.ipam.driver,
        ipam_options: response
            .ipam
            .options
            .map_or_else(BTreeMap::new, BoundedMap::into_inner),
        ipv4_network,
        ipv4_gateway,
        options: response
            .options
            .map_or_else(BTreeMap::new, BoundedMap::into_inner),
        labels: response
            .labels
            .map_or_else(BTreeMap::new, BoundedMap::into_inner),
        containers,
    })
}

#[cfg(unix)]
fn normalize_network_endpoint(
    id: String,
    endpoint: NetworkContainerResponse,
) -> Result<(String, NetworkEndpoint), EngineApiError> {
    require_object_id(&id)?;
    require_object_id(&endpoint.endpoint_id)?;
    if endpoint.name.is_empty()
        || endpoint.mac_address.is_empty()
        || !endpoint.ipv6_address.is_empty()
    {
        return Err(EngineApiError::InvalidResponse);
    }
    let (address, prefix) = parse_ipv4_address_prefix(&endpoint.ipv4_address)?;
    Ok((
        id,
        NetworkEndpoint {
            name: endpoint.name,
            endpoint_id: endpoint.endpoint_id,
            mac_address: endpoint.mac_address,
            ipv4_address: address,
            ipv4_prefix: prefix,
        },
    ))
}

#[cfg(unix)]
fn parse_ipv4_network(value: &str) -> Result<Ipv4Network, EngineApiError> {
    let (address, prefix) = parse_ipv4_address_prefix(value)?;
    if !(8..=30).contains(&prefix) || !address.is_private() {
        return Err(EngineApiError::InvalidResponse);
    }
    let mask = u32::MAX << (32 - prefix);
    if u32::from(address) & mask != u32::from(address) {
        return Err(EngineApiError::InvalidResponse);
    }
    Ok(Ipv4Network {
        network: address,
        prefix,
    })
}

#[cfg(unix)]
fn parse_ipv4_address_prefix(value: &str) -> Result<(Ipv4Addr, u8), EngineApiError> {
    let (address_text, prefix_text) = value
        .split_once('/')
        .ok_or(EngineApiError::InvalidResponse)?;
    let address = Ipv4Addr::from_str(address_text).map_err(|_| EngineApiError::InvalidResponse)?;
    let prefix = prefix_text
        .parse::<u8>()
        .map_err(|_| EngineApiError::InvalidResponse)?;
    if address.to_string() != address_text
        || prefix.to_string() != prefix_text
        || prefix > 32
        || format!("{address}/{prefix}") != value
    {
        return Err(EngineApiError::InvalidResponse);
    }
    Ok((address, prefix))
}

#[cfg(unix)]
fn parse_canonical_ipv4_address(value: &str) -> Result<Ipv4Addr, EngineApiError> {
    let address = Ipv4Addr::from_str(value).map_err(|_| EngineApiError::InvalidResponse)?;
    if address.to_string() != value {
        return Err(EngineApiError::InvalidResponse);
    }
    Ok(address)
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
    let capture_logs = normalize_log_configuration(&host.log_config, &response.log_path)?;
    let (primary_network, networks) = normalize_container_networks(
        &response.id,
        &name,
        state,
        &host.network_mode,
        &response.network_settings,
    )?;
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
            primary_network.as_deref(),
            &networks,
            state,
            capture_logs,
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
            primary_network,
            networks,
            capture_logs,
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
fn running_results_target(state: &ContainerStateResponse) -> bool {
    state.status == "running"
        && state.running
        && !state.paused
        && !state.restarting
        && !state.out_of_memory
        && !state.dead
        && state.pid > 0
        && state.exit_code == 0
        && state.error.is_empty()
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn exact_isolation(
    config: &ContainerConfigResponse,
    host: &HostConfigResponse,
    network: &NetworkSettingsResponse,
    expected_hostname: &str,
    primary_network: Option<&str>,
    networks: &BTreeMap<String, ContainerNetworkAttachment>,
    state: EngineContainerState,
    capture_logs: bool,
) -> bool {
    exact_container_config(config, expected_hostname, networks.is_empty())
        && exact_host_runtime(host, primary_network)
        && exact_host_scheduling(host)
        && exact_host_memory(host)
        && exact_host_resource_surface(host, capture_logs)
        && exact_host_paths(host)
        && exact_network(network, networks, state)
}

#[cfg(unix)]
fn exact_container_config(
    config: &ContainerConfigResponse,
    expected_hostname: &str,
    network_disabled: bool,
) -> bool {
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
        && config.network_disabled == network_disabled
        && config.healthcheck.is_disabled()
        && config.stop_signal == "SIGKILL"
        && config.stop_timeout == Some(0)
        && config.mac_address.as_ref().is_none_or(String::is_empty)
}

#[cfg(unix)]
fn exact_host_runtime(host: &HostConfigResponse, primary_network: Option<&str>) -> bool {
    host.binds.as_ref().is_none_or(BoundedVec::is_empty)
        && host.container_id_file.is_empty()
        && host.network_mode == primary_network.unwrap_or("none")
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
        // Docker v1.48 reports the requested `false` either directly while
        // created or normalized to null after start; `true` is never accepted.
        && host.oom_kill_disable.is_none_or(|disabled| !disabled)
        && host.pids_limit > 0
}

#[cfg(unix)]
fn exact_host_resource_surface(host: &HostConfigResponse, capture_logs: bool) -> bool {
    host.ulimits.is_empty()
        && !host.init
        && (if capture_logs {
            host.log_config.driver == "json-file"
                && host.log_config.options.clone().into_inner()
                    == BTreeMap::from([
                        ("compress".to_owned(), "false".to_owned()),
                        ("max-file".to_owned(), "1".to_owned()),
                        ("max-size".to_owned(), "64k".to_owned()),
                    ])
        } else {
            host.log_config.driver == "none" && host.log_config.options.is_empty()
        })
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
fn normalize_log_configuration(
    log: &LogConfigResponse,
    log_path: &str,
) -> Result<bool, EngineApiError> {
    match log.driver.as_str() {
        "none" if log.options.is_empty() && log_path.is_empty() => Ok(false),
        "json-file"
            if !log_path.is_empty()
                && log.options.clone().into_inner()
                    == BTreeMap::from([
                        ("compress".to_owned(), "false".to_owned()),
                        ("max-file".to_owned(), "1".to_owned()),
                        ("max-size".to_owned(), "64k".to_owned()),
                    ]) =>
        {
            Ok(true)
        }
        _ => Err(EngineApiError::InvalidResponse),
    }
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
fn normalize_container_networks(
    container_id: &str,
    container_name: &str,
    state: EngineContainerState,
    network_mode: &str,
    network: &NetworkSettingsResponse,
) -> Result<(Option<String>, BTreeMap<String, ContainerNetworkAttachment>), EngineApiError> {
    let networks = network
        .networks
        .clone()
        .into_inner()
        .into_iter()
        .map(|(name, endpoint)| {
            if name.is_empty()
                || name.len() > 255
                || endpoint
                    .links
                    .as_ref()
                    .is_some_and(|links| !links.is_empty())
                || endpoint
                    .driver_options
                    .as_ref()
                    .is_some_and(|options| !options.is_empty())
                || endpoint.gateway_priority != 0
            {
                return Err(EngineApiError::InvalidResponse);
            }
            let ipam = endpoint
                .ipam_config
                .as_ref()
                .ok_or(EngineApiError::InvalidResponse)?;
            let ipv4_address = ipam
                .ipv4_address
                .parse::<Ipv4Addr>()
                .map_err(|_| EngineApiError::InvalidResponse)?;
            if ipv4_address.to_string() != ipam.ipv4_address
                || !ipv4_address.is_private()
                || !ipam.ipv6_address.is_empty()
                || ipam
                    .link_local_ips
                    .as_ref()
                    .is_some_and(|values| !values.is_empty())
            {
                return Err(EngineApiError::InvalidResponse);
            }
            let aliases = endpoint
                .aliases
                .clone()
                .map_or_else(Vec::new, BoundedVec::into_inner);
            if aliases.iter().any(|alias| {
                alias.is_empty()
                    || alias.len() > 255
                    || !alias.is_ascii()
                    || alias.bytes().any(|byte| {
                        byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'/'
                    })
            }) {
                return Err(EngineApiError::InvalidResponse);
            }
            if !exact_endpoint_runtime(
                &endpoint,
                state,
                container_id,
                container_name,
                ipv4_address,
                &aliases,
            ) {
                return Err(EngineApiError::InvalidResponse);
            }
            Ok((
                name,
                ContainerNetworkAttachment {
                    network_id: endpoint.network_id,
                    ipv4_address,
                    aliases,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let primary = if networks.is_empty() {
        if network_mode != "none" {
            return Err(EngineApiError::InvalidResponse);
        }
        None
    } else if networks.contains_key(network_mode) {
        Some(network_mode.to_owned())
    } else {
        return Err(EngineApiError::InvalidResponse);
    };
    Ok((primary, networks))
}

#[cfg(unix)]
fn exact_endpoint_runtime(
    endpoint: &EndpointSettingsResponse,
    state: EngineContainerState,
    container_id: &str,
    container_name: &str,
    ipv4_address: Ipv4Addr,
    aliases: &[String],
) -> bool {
    let common = endpoint.gateway.is_empty()
        && endpoint.ipv6_gateway.is_empty()
        && endpoint.global_ipv6_address.is_empty()
        && endpoint.global_ipv6_prefix_length == 0;
    if !common {
        return false;
    }
    let Some(short_id) = container_id.get(..12) else {
        return false;
    };
    let expected_dns = std::iter::once(container_name)
        .chain(aliases.iter().map(String::as_str))
        .chain(std::iter::once(short_id));
    let runtime_empty = endpoint.endpoint_id.is_empty()
        && endpoint.ip_address.is_empty()
        && endpoint.mac_address.is_empty()
        && endpoint.ip_prefix_length == 0;
    match state {
        EngineContainerState::Created => {
            endpoint.network_id.is_empty() && runtime_empty && endpoint.dns_names.is_none()
        }
        EngineContainerState::Running => {
            valid_object_id(&endpoint.network_id)
                && valid_object_id(&endpoint.endpoint_id)
                && endpoint.ip_address == ipv4_address.to_string()
                && (8..=30).contains(&endpoint.ip_prefix_length)
                && !endpoint.mac_address.is_empty()
                && endpoint.dns_names.as_ref().is_some_and(|names| {
                    names.as_slice().iter().map(String::as_str).eq(expected_dns)
                })
        }
        EngineContainerState::Exited(_) => {
            valid_object_id(&endpoint.network_id)
                && runtime_empty
                && endpoint.dns_names.as_ref().is_some_and(|names| {
                    names.as_slice().iter().map(String::as_str).eq(expected_dns)
                })
        }
        EngineContainerState::Invalid => false,
    }
}

#[cfg(unix)]
fn exact_network(
    network: &NetworkSettingsResponse,
    networks: &BTreeMap<String, ContainerNetworkAttachment>,
    state: EngineContainerState,
) -> bool {
    let active = !networks.is_empty() && state == EngineContainerState::Running;
    (if active {
        valid_object_id(&network.sandbox_id) && !network.sandbox_key.is_empty()
    } else {
        network.sandbox_id.is_empty() && network.sandbox_key.is_empty()
    }) && network.ports.is_empty()
        && network.networks.len() == networks.len()
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
        let header = remaining
            .get(..DOCKER_STREAM_HEADER_BYTES)
            .ok_or(EngineApiError::InvalidResponse)?;
        if header[1..4] != [0, 0, 0] {
            return Err(EngineApiError::InvalidResponse);
        }
        let length = usize::try_from(u32::from_be_bytes(
            header[4..8]
                .try_into()
                .map_err(|_| EngineApiError::InvalidResponse)?,
        ))
        .map_err(|_| EngineApiError::InvalidResponse)?;
        let frame_end = DOCKER_STREAM_HEADER_BYTES
            .checked_add(length)
            .ok_or(EngineApiError::InvalidResponse)?;
        let payload = remaining
            .get(DOCKER_STREAM_HEADER_BYTES..frame_end)
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
        remaining = &remaining[frame_end..];
    }
    Ok((stdout, stderr))
}

#[cfg(unix)]
impl ContainerCreateRequest<'_> {
    fn new(definition: &ContainerDefinition) -> ContainerCreateRequest<'_> {
        let endpoints = definition
            .networks
            .iter()
            .map(|(name, attachment)| {
                (
                    name.clone(),
                    EndpointSettingsRequest {
                        ipam_config: EndpointIpamRequest {
                            ipv4_address: attachment.ipv4_address.to_string(),
                            ipv6_address: "",
                            link_local_ips: Vec::new(),
                        },
                        links: Vec::new(),
                        aliases: attachment.aliases.clone(),
                        network_id: attachment.network_id.clone(),
                        endpoint_id: "",
                        gateway: "",
                        ip_address: "",
                        ip_prefix_length: 0,
                        ipv6_gateway: "",
                        global_ipv6_address: "",
                        global_ipv6_prefix_length: 0,
                        mac_address: "",
                        driver_options: BTreeMap::new(),
                        gateway_priority: 0,
                    },
                )
            })
            .collect();
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
            network_disabled: definition.networks.is_empty(),
            labels: &definition.labels,
            on_build: Vec::new(),
            shell: Vec::new(),
            stop_signal: "SIGKILL",
            stop_timeout: 0,
            mac_address: "",
            host_config: HostConfigRequest::new(definition),
            networking_config: NetworkingConfigRequest { endpoints },
        }
    }
}

#[cfg(unix)]
impl<'a> NetworkCreateRequest<'a> {
    fn new(request: &'a CreateNetwork) -> Result<Self, EngineApiError> {
        let subnet = request.ipv4_network.canonical();
        let ipv4_network = parse_ipv4_network(&subnet)?;
        if ipv4_network != request.ipv4_network || !ipv4_network.usable(request.ipv4_gateway) {
            return Err(EngineApiError::InvalidResponse);
        }
        Ok(Self {
            name: &request.name,
            check_duplicate: true,
            driver: "bridge",
            internal: true,
            attachable: false,
            ingress: false,
            enable_ipv4: true,
            enable_ipv6: false,
            ipam: NetworkIpamRequest {
                driver: "default",
                options: BTreeMap::new(),
                config: [NetworkIpamConfigurationRequest {
                    subnet,
                    ip_range: "",
                    gateway: request.ipv4_gateway.to_string(),
                    auxiliary_addresses: BTreeMap::new(),
                }],
            },
            options: BTreeMap::from([("com.docker.network.bridge.gateway_mode_ipv4", "isolated")]),
            labels: &request.labels,
            config_from: NetworkConfigFromRequest { network: "" },
        })
    }
}

#[cfg(unix)]
impl<'a> HostConfigRequest<'a> {
    fn new(definition: &'a ContainerDefinition) -> Self {
        Self {
            binds: Vec::new(),
            container_id_file: "",
            log_config: if definition.capture_logs {
                LogConfigRequest {
                    driver: "json-file",
                    options: BTreeMap::from([
                        ("compress".to_owned(), "false".to_owned()),
                        ("max-file".to_owned(), "1".to_owned()),
                        ("max-size".to_owned(), "64k".to_owned()),
                    ]),
                }
            } else {
                LogConfigRequest {
                    driver: "none",
                    options: BTreeMap::new(),
                }
            },
            network_mode: definition.primary_network.as_deref().unwrap_or("none"),
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
    network_mode: &'a str,
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
    endpoints: BTreeMap<String, EndpointSettingsRequest>,
}

#[cfg(unix)]
#[derive(Serialize)]
struct EndpointSettingsRequest {
    #[serde(rename = "IPAMConfig")]
    ipam_config: EndpointIpamRequest,
    #[serde(rename = "Links")]
    links: Vec<String>,
    #[serde(rename = "Aliases")]
    aliases: Vec<String>,
    #[serde(rename = "NetworkID")]
    network_id: String,
    #[serde(rename = "EndpointID")]
    endpoint_id: &'static str,
    #[serde(rename = "Gateway")]
    gateway: &'static str,
    #[serde(rename = "IPAddress")]
    ip_address: &'static str,
    #[serde(rename = "IPPrefixLen")]
    ip_prefix_length: i64,
    #[serde(rename = "IPv6Gateway")]
    ipv6_gateway: &'static str,
    #[serde(rename = "GlobalIPv6Address")]
    global_ipv6_address: &'static str,
    #[serde(rename = "GlobalIPv6PrefixLen")]
    global_ipv6_prefix_length: i64,
    #[serde(rename = "MacAddress")]
    mac_address: &'static str,
    #[serde(rename = "DriverOpts")]
    driver_options: BTreeMap<String, String>,
    #[serde(rename = "GwPriority")]
    gateway_priority: i64,
}

#[cfg(unix)]
#[derive(Serialize)]
struct EndpointIpamRequest {
    #[serde(rename = "IPv4Address")]
    ipv4_address: String,
    #[serde(rename = "IPv6Address")]
    ipv6_address: &'static str,
    #[serde(rename = "LinkLocalIPs")]
    link_local_ips: Vec<String>,
}

#[cfg(unix)]
#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct NetworkCreateRequest<'a> {
    #[serde(rename = "Name")]
    name: &'a str,
    #[serde(rename = "CheckDuplicate")]
    check_duplicate: bool,
    #[serde(rename = "Driver")]
    driver: &'static str,
    #[serde(rename = "Internal")]
    internal: bool,
    #[serde(rename = "Attachable")]
    attachable: bool,
    #[serde(rename = "Ingress")]
    ingress: bool,
    #[serde(rename = "EnableIPv4")]
    enable_ipv4: bool,
    #[serde(rename = "EnableIPv6")]
    enable_ipv6: bool,
    #[serde(rename = "IPAM")]
    ipam: NetworkIpamRequest,
    #[serde(rename = "Options")]
    options: BTreeMap<&'static str, &'static str>,
    #[serde(rename = "Labels")]
    labels: &'a BTreeMap<String, String>,
    #[serde(rename = "ConfigFrom")]
    config_from: NetworkConfigFromRequest,
}

#[cfg(unix)]
#[derive(Serialize)]
struct NetworkIpamRequest {
    #[serde(rename = "Driver")]
    driver: &'static str,
    #[serde(rename = "Options")]
    options: BTreeMap<String, String>,
    #[serde(rename = "Config")]
    config: [NetworkIpamConfigurationRequest; 1],
}

#[cfg(unix)]
#[derive(Serialize)]
struct NetworkIpamConfigurationRequest {
    #[serde(rename = "Subnet")]
    subnet: String,
    #[serde(rename = "IPRange")]
    ip_range: &'static str,
    #[serde(rename = "Gateway")]
    gateway: String,
    #[serde(rename = "AuxiliaryAddresses")]
    auxiliary_addresses: BTreeMap<String, String>,
}

#[cfg(unix)]
#[derive(Serialize)]
struct NetworkConfigFromRequest {
    #[serde(rename = "Network")]
    network: &'static str,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkCreateResponse {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Warning")]
    warning: String,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct NetworkResponse {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Created")]
    created: String,
    #[serde(rename = "Scope")]
    scope: String,
    #[serde(rename = "Driver")]
    driver: String,
    #[serde(rename = "EnableIPv4")]
    enable_ipv4: bool,
    #[serde(rename = "EnableIPv6")]
    enable_ipv6: bool,
    #[serde(rename = "IPAM")]
    ipam: NetworkIpamResponse,
    #[serde(rename = "Internal")]
    internal: bool,
    #[serde(rename = "Attachable")]
    attachable: bool,
    #[serde(rename = "Ingress")]
    ingress: bool,
    #[serde(rename = "ConfigFrom")]
    config_from: NetworkConfigFromResponse,
    #[serde(rename = "ConfigOnly")]
    config_only: bool,
    #[serde(rename = "Options")]
    options: Option<BoundedMap<String, String, 32>>,
    #[serde(rename = "Labels")]
    labels: Option<BoundedMap<String, String, MAX_LABELS>>,
    #[serde(rename = "Containers")]
    containers: Option<BoundedMap<String, NetworkContainerResponse, MAX_NETWORK_CONTAINERS>>,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkIpamResponse {
    #[serde(rename = "Driver")]
    driver: String,
    #[serde(rename = "Options")]
    options: Option<BoundedMap<String, String, 32>>,
    #[serde(rename = "Config")]
    config: BoundedVec<NetworkIpamConfigurationResponse, MAX_NETWORK_IPAM_CONFIGS>,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkIpamConfigurationResponse {
    #[serde(rename = "Subnet")]
    subnet: String,
    #[serde(rename = "IPRange")]
    ip_range: Option<String>,
    #[serde(rename = "Gateway")]
    gateway: Option<String>,
    #[serde(rename = "AuxiliaryAddresses")]
    auxiliary_addresses: Option<BoundedMap<String, String, 32>>,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkConfigFromResponse {
    #[serde(rename = "Network")]
    network: String,
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkContainerResponse {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "EndpointID")]
    endpoint_id: String,
    #[serde(rename = "MacAddress")]
    mac_address: String,
    #[serde(rename = "IPv4Address")]
    ipv4_address: String,
    #[serde(rename = "IPv6Address")]
    ipv6_address: String,
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
    #[serde(rename = "RepoTags")]
    repo_tags: BoundedVec<String, MAX_REPO_TAGS>,
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
    #[serde(rename = "User", default)]
    user: String,
    #[serde(rename = "Entrypoint", default)]
    entrypoint: Option<BoundedVec<String, 4>>,
    #[serde(rename = "Cmd", default)]
    command: Option<BoundedVec<String, MAX_ARGUMENTS>>,
    #[serde(rename = "WorkingDir", default)]
    working_directory: String,
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
struct ResultsTargetResponse {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "State")]
    state: ContainerStateResponse,
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
    networks: BoundedMap<String, EndpointSettingsResponse, MAX_NETWORKS>,
}

#[cfg(unix)]
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointSettingsResponse {
    #[serde(rename = "IPAMConfig")]
    ipam_config: Option<EndpointIpamResponse>,
    #[serde(rename = "Links")]
    links: Option<BoundedVec<String, 16>>,
    #[serde(rename = "Aliases")]
    aliases: Option<BoundedVec<String, 16>>,
    #[serde(rename = "DriverOpts")]
    driver_options: Option<BoundedMap<String, String, 16>>,
    #[serde(rename = "GwPriority", default)]
    gateway_priority: i64,
    #[serde(rename = "NetworkID")]
    network_id: String,
    #[serde(rename = "EndpointID")]
    endpoint_id: String,
    #[serde(rename = "Gateway")]
    gateway: String,
    #[serde(rename = "IPAddress")]
    ip_address: String,
    #[serde(rename = "MacAddress")]
    mac_address: String,
    #[serde(rename = "IPPrefixLen")]
    ip_prefix_length: i64,
    #[serde(rename = "IPv6Gateway")]
    ipv6_gateway: String,
    #[serde(rename = "GlobalIPv6Address")]
    global_ipv6_address: String,
    #[serde(rename = "GlobalIPv6PrefixLen")]
    global_ipv6_prefix_length: i64,
    #[serde(rename = "DNSNames")]
    dns_names: Option<BoundedVec<String, 32>>,
}

#[cfg(unix)]
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointIpamResponse {
    #[serde(rename = "IPv4Address")]
    ipv4_address: String,
    #[serde(rename = "IPv6Address", default)]
    ipv6_address: String,
    #[serde(rename = "LinkLocalIPs", default)]
    link_local_ips: Option<BoundedVec<String, 8>>,
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
            // Docker v1.48 retains the positive host PID after the exec has
            // stopped; the created form above is the only accepted zero PID.
            && self.pid > 0
    }
}

#[derive(Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Exact independent Docker v1.48 capability fields.
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::Ipv4Addr, path::Path};

    use serde_json::{Value, json};

    use super::EngineApiError;
    use super::{
        ContainerCustodyResponse, ContainerDefinition, CreateNetwork, DEFAULT_CONTAINER_PATH,
        EngineApi, EngineContainerState, ExecInspectResponse, HttpEngine, ImageResponse,
        InfoResponse, Ipv4Network, MASKED_PATHS, NetworkCreateRequest, NetworkResponse,
        READ_ONLY_PATHS, SandboxEngineApi, normalize_container, normalize_container_custody,
        normalize_image, normalize_network, valid_object_id,
    };
    use super::{EngineExecRequest, PreparedEngineExec};
    use crate::ApiVersion;

    #[test]
    fn accepts_only_full_canonical_container_ids() {
        assert!(valid_object_id(&"a".repeat(64)));
        assert!(!valid_object_id(&"a".repeat(63)));
        assert!(!valid_object_id(&"g".repeat(64)));
        assert!(!valid_object_id(&"A".repeat(64)));
    }

    #[test]
    fn daemon_security_options_are_retained_as_bounded_engine_evidence() {
        let value = json!({
            "ID": "relay-engine",
            "ServerVersion": "29.7.2",
            "Architecture": "x86_64",
            "OSType": "linux",
            "SecurityOptions": [
                "name=seccomp,profile=builtin",
                "name=userns",
                "name=cgroupns"
            ],
            "MemoryLimit": true,
            "SwapLimit": true,
            "CpuCfsPeriod": true,
            "CpuCfsQuota": true,
            "PidsLimit": true
        });
        let response: InfoResponse =
            serde_json::from_value(value.clone()).expect("Docker info response");
        assert_eq!(
            response
                .security_options
                .expect("security options")
                .as_slice(),
            [
                "name=seccomp,profile=builtin",
                "name=userns",
                "name=cgroupns"
            ]
        );
        for field in [
            "MemoryLimit",
            "SwapLimit",
            "CpuCfsPeriod",
            "CpuCfsQuota",
            "PidsLimit",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().expect("info object").remove(field);
            assert!(serde_json::from_value::<InfoResponse>(missing).is_err());
            for invalid in [Value::Null, json!("true")] {
                let mut wrong_type = value.clone();
                wrong_type[field] = invalid;
                assert!(serde_json::from_value::<InfoResponse>(wrong_type).is_err());
            }
        }
    }

    fn network_json() -> Value {
        let mut value = json!({
            "Name": "automata-results-network",
            "Id": "a".repeat(64),
            "Created": "2026-08-16T00:00:00Z",
            "Scope": "local",
            "Driver": "bridge",
            "EnableIPv4": true,
            "EnableIPv6": false,
            "IPAM": {
                "Driver": "default",
                "Options": null,
                "Config": [{
                    "Subnet": "10.31.0.0/29",
                    "IPRange": "",
                    "Gateway": "10.31.0.1",
                    "AuxiliaryAddresses": null
                }]
            },
            "Internal": true,
            "Attachable": false,
            "Ingress": false,
            "ConfigFrom": {"Network": ""},
            "ConfigOnly": false,
            "Options": {
                "com.docker.network.bridge.gateway_mode_ipv4": "isolated"
            },
            "Labels": {"io.automata.test": "true"},
            "Containers": {}
        });
        let containers = value
            .pointer_mut("/Containers")
            .expect("containers fixture")
            .as_object_mut()
            .expect("containers object");
        containers.insert(
            "b".repeat(64),
            json!({
                "Name": "automata-results-proxy",
                "EndpointID": "c".repeat(64),
                "MacAddress": "02:42:0a:1f:00:02",
                "IPv4Address": "10.31.0.2/29",
                "IPv6Address": ""
            }),
        );
        containers.insert(
            "d".repeat(64),
            json!({
                "Name": "automata-job",
                "EndpointID": "e".repeat(64),
                "MacAddress": "02:42:0a:1f:00:03",
                "IPv4Address": "10.31.0.3/29",
                "IPv6Address": ""
            }),
        );
        value
    }

    fn normalized_network(value: Value) -> Result<super::InspectedNetwork, super::EngineApiError> {
        let response: NetworkResponse =
            serde_json::from_value(value).map_err(|_| super::EngineApiError::InvalidResponse)?;
        normalize_network(response)
    }

    #[test]
    fn network_create_request_contains_one_exact_ipv4_configuration() {
        let labels = BTreeMap::from([("io.automata.test".to_owned(), "true".to_owned())]);
        let request = CreateNetwork {
            name: "automata-results-network".to_owned(),
            labels: labels.clone(),
            ipv4_network: Ipv4Network {
                network: Ipv4Addr::new(10, 31, 0, 0),
                prefix: 29,
            },
            ipv4_gateway: Ipv4Addr::new(10, 31, 0, 1),
        };
        let body = NetworkCreateRequest::new(&request).expect("canonical network request");
        assert_eq!(
            serde_json::to_value(body).expect("serialize network request"),
            json!({
                "Name": "automata-results-network",
                "CheckDuplicate": true,
                "Driver": "bridge",
                "Internal": true,
                "Attachable": false,
                "Ingress": false,
                "EnableIPv4": true,
                "EnableIPv6": false,
                "IPAM": {
                    "Driver": "default",
                    "Options": {},
                    "Config": [{
                        "Subnet": "10.31.0.0/29",
                        "IPRange": "",
                        "Gateway": "10.31.0.1",
                        "AuxiliaryAddresses": {}
                    }]
                },
                "Options": {
                    "com.docker.network.bridge.gateway_mode_ipv4": "isolated"
                },
                "Labels": labels,
                "ConfigFrom": {"Network": ""}
            })
        );
    }

    #[test]
    fn network_create_request_rejects_noncanonical_or_reserved_ipv4_configuration() {
        let request = |network, prefix, gateway| CreateNetwork {
            name: "automata-results-network".to_owned(),
            labels: BTreeMap::new(),
            ipv4_network: Ipv4Network { network, prefix },
            ipv4_gateway: gateway,
        };
        for invalid in [
            request(Ipv4Addr::new(10, 31, 0, 1), 29, Ipv4Addr::new(10, 31, 0, 2)),
            request(Ipv4Addr::new(10, 31, 0, 0), 29, Ipv4Addr::new(10, 31, 0, 0)),
            request(Ipv4Addr::new(10, 31, 0, 0), 29, Ipv4Addr::new(10, 31, 0, 7)),
            request(Ipv4Addr::new(10, 31, 0, 0), 31, Ipv4Addr::new(10, 31, 0, 1)),
            request(Ipv4Addr::new(10, 31, 0, 0), 0, Ipv4Addr::new(10, 31, 0, 1)),
        ] {
            assert!(NetworkCreateRequest::new(&invalid).is_err());
        }
    }

    #[test]
    fn network_inspection_requires_one_canonical_usable_gateway() {
        let inspected = normalized_network(network_json()).expect("canonical network response");
        assert_eq!(
            inspected.ipv4_network,
            Ipv4Network {
                network: Ipv4Addr::new(10, 31, 0, 0),
                prefix: 29,
            }
        );
        assert_eq!(inspected.ipv4_gateway, Ipv4Addr::new(10, 31, 0, 1));

        for gateway in [
            Value::Null,
            json!(""),
            json!("10.31.0.01"),
            json!("10.31.0.1/29"),
            json!("10.31.0.0"),
            json!("10.31.0.7"),
            json!("10.31.0.8"),
        ] {
            let mut value = network_json();
            *value
                .pointer_mut("/IPAM/Config/0/Gateway")
                .expect("gateway fixture") = gateway;
            assert!(normalized_network(value).is_err());
        }

        let mut missing = network_json();
        missing
            .pointer_mut("/IPAM/Config/0")
            .expect("configuration fixture")
            .as_object_mut()
            .expect("configuration object")
            .remove("Gateway");
        assert!(normalized_network(missing).is_err());
    }

    #[test]
    fn network_inspection_rejects_duplicate_and_gateway_endpoint_addresses() {
        let mut duplicate = network_json();
        *duplicate
            .pointer_mut(&format!("/Containers/{}/IPv4Address", "d".repeat(64)))
            .expect("second endpoint fixture") = json!("10.31.0.2/29");
        assert!(normalized_network(duplicate).is_err());

        let mut gateway = network_json();
        *gateway
            .pointer_mut(&format!("/Containers/{}/IPv4Address", "b".repeat(64)))
            .expect("first endpoint fixture") = json!("10.31.0.1/29");
        assert!(normalized_network(gateway).is_err());
    }

    fn image_json(environment: &Value) -> Value {
        json!({
            "Id": format!("sha256:{}", "2".repeat(64)),
            "RepoTags": [],
            "RepoDigests": [format!("registry.example/job@sha256:{}", "1".repeat(64))],
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {
                "Env": environment,
                "Volumes": null,
                "Labels": {"org.opencontainers.image.version": "1"}
            }
        })
    }

    #[test]
    fn image_environment_is_reduced_to_unique_sorted_names() {
        let response: ImageResponse =
            serde_json::from_value(image_json(&json!(["Z=value", "PATH=/bin", "A="])))
                .expect("image response");
        let inspected = normalize_image(response).expect("canonical image environment");
        assert_eq!(inspected.environment_names, ["A", "PATH", "Z"]);
        assert!(!inspected.default_path_only);
        let response = serde_json::from_value(image_json(&json!([DEFAULT_CONTAINER_PATH])))
            .expect("default PATH image response");
        let inspected = normalize_image(response).expect("exact default PATH");
        assert_eq!(inspected.environment_names, ["PATH"]);
        assert!(inspected.default_path_only);
        for environment in [json!(["PATH=/bin", "PATH=/usr/bin"]), json!(["bad-name=x"])] {
            let response =
                serde_json::from_value(image_json(&environment)).expect("image response");
            assert!(normalize_image(response).is_err());
        }
    }

    #[test]
    fn image_references_preserve_classic_and_containerd_import_representations() {
        let reference = format!(
            "automata.local/automata-ci-service-proxy:manifest-{}",
            "3".repeat(64)
        );
        let digest = format!(
            "automata.local/automata-ci-service-proxy@sha256:{}",
            "3".repeat(64)
        );
        let mut classic = image_json(&json!([]));
        classic["RepoTags"] = json!([reference]);
        classic["RepoDigests"] = json!([]);
        let classic =
            normalize_image(serde_json::from_value(classic).expect("typed classic imported image"))
                .expect("classic imported image");
        assert_eq!(
            classic.repo_tags.as_slice(),
            std::slice::from_ref(&reference)
        );
        assert!(classic.repo_digests.is_empty());

        let mut containerd = image_json(&json!([]));
        containerd["RepoTags"] = json!([reference]);
        containerd["RepoDigests"] = json!([digest]);
        let containerd = normalize_image(
            serde_json::from_value(containerd).expect("typed containerd imported image"),
        )
        .expect("containerd imported image");
        assert_eq!(containerd.repo_tags, [reference]);
        assert_eq!(containerd.repo_digests, [digest]);
    }

    #[test]
    fn image_port_and_healthcheck_defaults_are_captured_before_create() {
        for exposed_ports in [Value::Null, json!({})] {
            let mut value = image_json(&json!([]));
            value["Config"]["ExposedPorts"] = exposed_ports;
            let image = normalize_image(
                serde_json::from_value(value).expect("typed empty exposed-port image"),
            )
            .expect("empty exposed ports");
            assert!(image.declared_exposed_ports.is_empty());
            assert!(!image.has_healthcheck);
        }

        let mut port = image_json(&json!([]));
        port["Config"]["ExposedPorts"] = json!({"8080/tcp": {}});
        assert_eq!(
            normalize_image(serde_json::from_value(port).expect("typed exposed-port image"))
                .expect("canonical exposed port")
                .declared_exposed_ports,
            ["8080/tcp"]
        );

        for healthcheck in [
            json!({}),
            json!({"Test": null}),
            json!({"Test": ["NONE"]}),
            json!({
                "Test": ["CMD-SHELL", "exit 0"],
                "Interval": 1_000_000_000_i64,
                "Timeout": 2_000_000_000_i64,
                "Retries": 3,
                "StartPeriod": 4_000_000_000_i64,
                "StartInterval": 5_000_000_000_i64
            }),
        ] {
            let mut value = image_json(&json!([]));
            value["Config"]["Healthcheck"] = healthcheck;
            assert!(
                normalize_image(serde_json::from_value(value).expect("typed image healthcheck"))
                    .expect("canonical image")
                    .has_healthcheck
            );
        }

        let mut too_many_ports = image_json(&json!([]));
        too_many_ports["Config"]["ExposedPorts"] = Value::Object(
            (0..65)
                .map(|port| (format!("{port}/tcp"), json!({})))
                .collect(),
        );
        assert!(serde_json::from_value::<ImageResponse>(too_many_ports).is_err());

        let mut too_many_tests = image_json(&json!([]));
        too_many_tests["Config"]["Healthcheck"] = json!({"Test": vec!["x"; 9]});
        assert!(serde_json::from_value::<ImageResponse>(too_many_tests).is_err());
    }

    fn expected_definition() -> ContainerDefinition {
        ContainerDefinition {
            name: "automata-exact-fixture".to_owned(),
            image: format!("registry.example/job@sha256:{}", "1".repeat(64)),
            entrypoint: "/automata/bin/automata-ci-sandbox-guest".to_owned(),
            arguments: vec!["serve-local".to_owned()],
            labels: BTreeMap::from([("io.automata.test".to_owned(), "true".to_owned())]),
            environment: vec!["PATH=".to_owned()],
            tmpfs: BTreeMap::from([
                (
                    "/workspace/repository".to_owned(),
                    "rw,exec,nosuid,nodev,size=268435456,mode=0777,uid=0,gid=0".to_owned(),
                ),
                (
                    "/automata-control".to_owned(),
                    "rw,exec,nosuid,nodev,size=67108864,mode=0733,uid=65533,gid=65532".to_owned(),
                ),
            ]),
            working_directory: "/workspace/repository".to_owned(),
            user: "0:0".to_owned(),
            read_only_root: false,
            memory_bytes: 268_435_456,
            nano_cpus: 1_000_000_000,
            pids_limit: 128,
            primary_network: None,
            networks: BTreeMap::new(),
            capture_logs: false,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn realized_container_json() -> Value {
        let id = "a".repeat(64);
        let definition = expected_definition();
        let config = json!({
            "Hostname": &id[..12],
            "Domainname": "",
            "User": definition.user,
            "AttachStdin": false,
            "AttachStdout": false,
            "AttachStderr": false,
            "Tty": false,
            "OpenStdin": false,
            "StdinOnce": false,
            "ArgsEscaped": false,
            "Env": definition.environment,
            "Cmd": definition.arguments,
            "Healthcheck": {"Test": ["NONE"]},
            "Image": definition.image,
            "ExposedPorts": {},
            "Volumes": null,
            "WorkingDir": definition.working_directory,
            "Entrypoint": [definition.entrypoint],
            "NetworkDisabled": true,
            "Labels": definition.labels,
            "OnBuild": [],
            "Shell": [],
            "StopSignal": "SIGKILL",
            "StopTimeout": 0,
            "MacAddress": ""
        });
        let mut host_config = json!({
            "Binds": [],
            "ContainerIDFile": "",
            "LogConfig": {"Type": "none", "Config": {}},
            "NetworkMode": "none",
            "PortBindings": {},
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "AutoRemove": false,
            "VolumeDriver": "",
            "VolumesFrom": [],
            "CapAdd": [],
            "CapDrop": ["ALL"],
            "CgroupnsMode": "private",
            "Dns": [],
            "DnsOptions": [],
            "DnsSearch": [],
            "ExtraHosts": [],
            "GroupAdd": [],
            "IpcMode": "private",
            "Cgroup": "",
            "Links": null,
            "OomScoreAdj": 0,
            "PidMode": "",
            "Privileged": false,
            "PublishAllPorts": false,
            "ReadonlyRootfs": false,
            "SecurityOpt": ["no-new-privileges=true", "seccomp=builtin"],
            "UTSMode": "",
            "UsernsMode": "",
            "Runtime": "runc",
            "Isolation": "",
            "ShmSize": 67_108_864,
            "ConsoleSize": [0, 0]
        });
        let resource_config = json!({
            "CpuShares": 0,
            "CgroupParent": "",
            "BlkioWeight": 0,
            "BlkioWeightDevice": null,
            "BlkioDeviceReadBps": null,
            "BlkioDeviceWriteBps": null,
            "BlkioDeviceReadIOps": null,
            "BlkioDeviceWriteIOps": null,
            "CpuPeriod": 0,
            "CpuQuota": 0,
            "CpuRealtimePeriod": 0,
            "CpuRealtimeRuntime": 0,
            "CpusetCpus": "",
            "CpusetMems": "",
            "Memory": 268_435_456,
            "MemoryReservation": 0,
            "MemorySwap": 268_435_456,
            "MemorySwappiness": null,
            "NanoCpus": 1_000_000_000,
            "OomKillDisable": null,
            "PidsLimit": 128,
            "Ulimits": [],
            "Devices": [],
            "DeviceCgroupRules": [],
            "DeviceRequests": [],
            "Mounts": null,
            "Tmpfs": definition.tmpfs,
            "Init": false,
            "CpuCount": 0,
            "CpuPercent": 0,
            "IOMaximumIOps": 0,
            "IOMaximumBandwidth": 0,
            "StorageOpt": {},
            "Sysctls": {},
            "MaskedPaths": MASKED_PATHS,
            "ReadonlyPaths": READ_ONLY_PATHS
        });
        host_config.as_object_mut().expect("host object").extend(
            resource_config
                .as_object()
                .expect("resource object")
                .clone(),
        );
        json!({
            "Id": id,
            "Image": format!("sha256:{}", "2".repeat(64)),
            "Name": format!("/{}", definition.name),
            "Created": "2026-08-16T00:00:00Z",
            "Path": definition.entrypoint,
            "Args": definition.arguments,
            "ResolvConfPath": "/var/lib/docker/containers/fixture/resolv.conf",
            "HostnamePath": "/var/lib/docker/containers/fixture/hostname",
            "HostsPath": "/var/lib/docker/containers/fixture/hosts",
            "LogPath": "",
            "RestartCount": 0,
            "Driver": "overlay2",
            "Platform": "linux",
            "MountLabel": "",
            "ProcessLabel": "",
            "AppArmorProfile": "",
            "ExecIDs": null,
            "State": {
                "Status": "running",
                "Running": true,
                "Paused": false,
                "Restarting": false,
                "OOMKilled": false,
                "Dead": false,
                "Pid": 42,
                "ExitCode": 0,
                "Error": "",
                "StartedAt": "2026-08-16T00:00:01Z",
                "FinishedAt": "0001-01-01T00:00:00Z"
            },
            "Config": config,
            "HostConfig": host_config,
            "Mounts": [],
            "NetworkSettings": {
                "SandboxID": "",
                "SandboxKey": "",
                "Ports": {},
                "Networks": {}
            },
            "GraphDriver": {"Name": "overlay2", "Data": {}}
        })
    }

    fn normalized(value: Value) -> Result<super::InspectedContainer, super::EngineApiError> {
        let response =
            serde_json::from_value(value).map_err(|_| super::EngineApiError::InvalidResponse)?;
        normalize_container(response)
    }

    #[test]
    fn exact_realized_configuration_matches_the_generated_contract() {
        let container = normalized(realized_container_json()).expect("valid inspect fixture");
        assert_eq!(container.definition, expected_definition());
        assert_eq!(container.state, EngineContainerState::Running);
        assert!(container.isolated);
    }

    #[test]
    fn custody_parser_survives_runtime_defaults_that_execution_rejects() {
        let mut value = realized_container_json();
        value["AppArmorProfile"] = json!("docker-default");
        value["MountLabel"] = json!("system_u:object_r:container_file_t:s0:c1,c2");
        value["ProcessLabel"] = json!("system_u:system_r:container_t:s0:c1,c2");
        value["LogPath"] = json!("/var/lib/docker/containers/fixture-json.log");
        value["HostConfig"]["Ulimits"] = json!([{"Name": "nofile", "Soft": 1024, "Hard": 1024}]);
        assert!(normalized(value.clone()).is_err());

        let custody = normalize_container_custody(
            serde_json::from_value::<ContainerCustodyResponse>(value)
                .expect("minimal custody response"),
        )
        .expect("custody identity remains recoverable");
        assert_eq!(custody.name, expected_definition().name);
        assert_eq!(custody.id, "a".repeat(64));
        assert_eq!(custody.state, EngineContainerState::Running);
    }

    #[test]
    fn results_target_requires_one_exact_running_engine_state() {
        let running = json!({
            "Status": "running",
            "Running": true,
            "Paused": false,
            "Restarting": false,
            "OOMKilled": false,
            "Dead": false,
            "Pid": 42,
            "ExitCode": 0,
            "Error": "",
            "StartedAt": "2026-08-16T00:00:01Z",
            "FinishedAt": "0001-01-01T00:00:00Z"
        });
        let accepted = serde_json::from_value(running.clone()).expect("running state");
        assert!(super::running_results_target(&accepted));
        for (pointer, replacement) in [
            ("/Status", json!("paused")),
            ("/Running", json!(false)),
            ("/Paused", json!(true)),
            ("/Restarting", json!(true)),
            ("/OOMKilled", json!(true)),
            ("/Dead", json!(true)),
            ("/Pid", json!(0)),
            ("/ExitCode", json!(1)),
            ("/Error", json!("failed")),
        ] {
            let mut state = running.clone();
            *state.pointer_mut(pointer).expect("state field") = replacement;
            let state = serde_json::from_value(state).expect("mutated state");
            assert!(!super::running_results_target(&state));
        }
    }

    #[test]
    fn endpoint_runtime_normalization_is_exact_for_each_lifecycle_state() {
        let container_id = "a".repeat(64);
        let container_name = "automata-results-proxy";
        let network_id = "b".repeat(64);
        let endpoint = |realized_network_id: &str,
                        aliases: Value,
                        endpoint_id: &str,
                        ip_address: &str,
                        prefix: i64,
                        mac_address: &str,
                        dns_names: Value| {
            serde_json::from_value::<super::EndpointSettingsResponse>(json!({
                "IPAMConfig": {"IPv4Address": "10.31.0.2", "IPv6Address": "", "LinkLocalIPs": []},
                "Links": null,
                "Aliases": aliases,
                "DriverOpts": null,
                "GwPriority": 0,
                "NetworkID": realized_network_id,
                "EndpointID": endpoint_id,
                "Gateway": "",
                "IPAddress": ip_address,
                "MacAddress": mac_address,
                "IPPrefixLen": prefix,
                "IPv6Gateway": "",
                "GlobalIPv6Address": "",
                "GlobalIPv6PrefixLen": 0,
                "DNSNames": dns_names,
            }))
            .expect("endpoint response")
        };
        let aliases = vec!["results.automata.invalid".to_owned()];
        let expected_dns = json!([
            container_name,
            "results.automata.invalid",
            &container_id[..12]
        ]);
        let created = endpoint("", Value::Null, "", "", 0, "", Value::Null);
        let running = endpoint(
            &network_id,
            json!(aliases),
            &"c".repeat(64),
            "10.31.0.2",
            29,
            "02:42:0a:1f:00:02",
            expected_dns.clone(),
        );
        let exited = endpoint(&network_id, json!(aliases), "", "", 0, "", expected_dns);
        let stale_created_network = endpoint(&network_id, Value::Null, "", "", 0, "", Value::Null);
        for (state, observed, accepted) in [
            (EngineContainerState::Created, &created, true),
            (EngineContainerState::Running, &running, true),
            (EngineContainerState::Exited(137), &exited, true),
            (EngineContainerState::Exited(137), &created, false),
            (EngineContainerState::Created, &stale_created_network, false),
            (EngineContainerState::Invalid, &created, false),
        ] {
            let normalized_aliases = observed
                .aliases
                .clone()
                .map_or_else(Vec::new, super::super::transport::BoundedVec::into_inner);
            assert_eq!(
                super::exact_endpoint_runtime(
                    observed,
                    state,
                    &container_id,
                    container_name,
                    "10.31.0.2".parse().expect("IPv4"),
                    &normalized_aliases,
                ),
                accepted,
                "state {state:?}"
            );
        }
    }

    #[test]
    fn transient_exec_ids_must_be_bounded_canonical_and_unique() {
        let mut value = realized_container_json();
        *value.pointer_mut("/ExecIDs").expect("fixture pointer") =
            json!(["a".repeat(64), "b".repeat(64)]);
        assert!(normalized(value.clone()).is_ok());

        for invalid in [
            json!(["a".repeat(63)]),
            json!(["A".repeat(64)]),
            json!(["a".repeat(64), "a".repeat(64)]),
        ] {
            *value.pointer_mut("/ExecIDs").expect("fixture pointer") = invalid;
            assert!(normalized(value.clone()).is_err());
        }

        *value.pointer_mut("/ExecIDs").expect("fixture pointer") = Value::Array(
            (0..17)
                .map(|index| json!(format!("{index:064x}")))
                .collect(),
        );
        assert!(normalized(value).is_err());
    }

    #[test]
    fn oom_kill_disable_accepts_only_the_two_v1_48_false_normalizations() {
        for realized in [Value::Null, json!(false)] {
            let mut value = realized_container_json();
            *value
                .pointer_mut("/HostConfig/OomKillDisable")
                .expect("fixture pointer") = realized;
            assert!(normalized(value).expect("false form").isolated);
        }
        let mut value = realized_container_json();
        *value
            .pointer_mut("/HostConfig/OomKillDisable")
            .expect("fixture pointer") = json!(true);
        assert!(!normalized(value).expect("typed true form").isolated);
    }

    fn exec_inspect_json(running: bool, exit_code: &Value, pid: i64) -> Value {
        json!({
            "ID": "a".repeat(64),
            "Running": running,
            "ExitCode": exit_code,
            "ProcessConfig": {
                "tty": false,
                "entrypoint": "/automata-control/automata-ci-sandbox-guest",
                "arguments": ["local-client"],
                "privileged": false,
                "user": "65532:65532"
            },
            "OpenStdin": true,
            "OpenStderr": true,
            "OpenStdout": true,
            "CanRemove": false,
            "ContainerID": "b".repeat(64),
            "DetachKeys": "",
            "Pid": pid
        })
    }

    #[test]
    fn exec_inspection_has_disjoint_exact_created_and_finished_states() {
        let command = vec![
            "/automata-control/automata-ci-sandbox-guest".to_owned(),
            "local-client".to_owned(),
        ];
        let created: ExecInspectResponse =
            serde_json::from_value(exec_inspect_json(false, &Value::Null, 0))
                .expect("created exec");
        assert!(
            created.matches_created(&"a".repeat(64), &"b".repeat(64), &command, "65532:65532",)
        );

        let prepared = PreparedEngineExec {
            id: "a".repeat(64),
            container_id: "b".repeat(64),
            command: command.clone(),
            user: "65532:65532".to_owned(),
        };
        let request = EngineExecRequest {
            container_id: prepared.container_id.clone(),
            command,
            user: prepared.user.clone(),
            stdin: Vec::new(),
            stdout_limit: 1,
            stderr_limit: 1,
            timeout: std::time::Duration::from_secs(1),
        };
        let finished: ExecInspectResponse =
            serde_json::from_value(exec_inspect_json(false, &json!(0), 42)).expect("finished exec");
        assert!(finished.matches_finished(&prepared, &request));
        for invalid in [
            exec_inspect_json(false, &json!(0), 0),
            exec_inspect_json(true, &json!(0), 42),
        ] {
            let invalid: ExecInspectResponse =
                serde_json::from_value(invalid).expect("typed invalid exec state");
            assert!(!invalid.matches_finished(&prepared, &request));
        }
        let mut unknown = exec_inspect_json(false, &Value::Null, 0);
        unknown
            .as_object_mut()
            .expect("exec object")
            .insert("Unexpected".to_owned(), json!(true));
        assert!(serde_json::from_value::<ExecInspectResponse>(unknown).is_err());
    }

    #[test]
    fn high_risk_realized_configuration_tampering_fails_closed() {
        for (pointer, replacement) in [
            ("/Config/Env", json!(["PATH=", "SECRET=leaked"])),
            ("/Config/Volumes", json!({"/host": {}})),
            ("/Config/ExposedPorts", json!({"8080/tcp": {}})),
            ("/HostConfig/NetworkMode", json!("host")),
            ("/HostConfig/Privileged", json!(true)),
            ("/HostConfig/Binds", json!(["/host:/guest"])),
            ("/HostConfig/Tmpfs", json!({"/foreign": "rw"})),
            (
                "/HostConfig/Tmpfs/~1automata-control",
                json!("rw,exec,size=33554432,mode=0733,uid=65533,gid=65532"),
            ),
            ("/HostConfig/Init", json!(true)),
            ("/HostConfig/OomKillDisable", json!(true)),
            ("/Mounts", json!([{"Type": "volume"}])),
            ("/HostConfig/Devices", json!([{"PathOnHost": "/dev/kvm"}])),
            ("/HostConfig/Sysctls", json!({"kernel.hostname": "foreign"})),
            ("/HostConfig/SecurityOpt", json!(["seccomp=unconfined"])),
            ("/HostConfig/ReadonlyRootfs", json!(true)),
            ("/NetworkSettings/Networks", json!({"bridge": {}})),
        ] {
            let mut value = realized_container_json();
            *value.pointer_mut(pointer).expect("fixture pointer") = replacement;
            if let Ok(container) = normalized(value) {
                assert!(
                    !container.isolated || container.definition != expected_definition(),
                    "accepted tamper at {pointer}"
                );
            }
        }
    }

    #[tokio::test]
    #[ignore = "creates and removes one exact internal Docker Engine 28 network"]
    async fn live_engine_28_internal_isolated_network_normalization_is_exact() {
        let engine = HttpEngine::connect_unix_socket(
            Path::new("/var/run/docker.sock"),
            ApiVersion {
                major: 1,
                minor: 48,
            },
        )
        .expect("Docker Engine socket");
        let facts = engine.engine_facts().await.expect("Engine facts");
        assert!(
            facts
                .server_version
                .split('.')
                .next()
                .and_then(|major| major.parse::<u64>().ok())
                .is_some_and(|major| major >= 28),
            "live gate requires Docker Engine 28 or newer"
        );
        let name = format!("automata-results-network-live-{}", uuid::Uuid::new_v4());
        let labels = BTreeMap::from([(
            "io.automata.test.results-network".to_owned(),
            "true".to_owned(),
        )]);
        let ipv4_network = Ipv4Network {
            network: Ipv4Addr::new(10, 255, 255, 248),
            prefix: 29,
        };
        let ipv4_gateway = Ipv4Addr::new(10, 255, 255, 249);
        let created_id = engine
            .create_network(CreateNetwork {
                name: name.clone(),
                labels: labels.clone(),
                ipv4_network: ipv4_network.clone(),
                ipv4_gateway,
            })
            .await
            .expect("create exact network");
        let verification = async {
            let inspected = engine
                .inspect_network(&name)
                .await?
                .ok_or(EngineApiError::InvalidResponse)?;
            let exact = inspected.id == created_id
                && inspected.name == name
                && inspected.driver == "bridge"
                && inspected.scope == "local"
                && inspected.enable_ipv4
                && !inspected.enable_ipv6
                && inspected.internal
                && !inspected.attachable
                && !inspected.ingress
                && !inspected.config_only
                && inspected.config_from.is_empty()
                && inspected.ipam_driver == "default"
                && inspected.ipam_options.is_empty()
                && inspected.ipv4_network == ipv4_network
                && inspected.ipv4_gateway == ipv4_gateway
                && inspected.options
                    == BTreeMap::from([(
                        "com.docker.network.bridge.gateway_mode_ipv4".to_owned(),
                        "isolated".to_owned(),
                    )])
                && inspected.labels == labels
                && inspected.containers.is_empty();
            Ok::<_, EngineApiError>(exact)
        }
        .await;
        engine
            .remove_network(&created_id)
            .await
            .expect("remove exact network");
        assert!(
            engine
                .inspect_network(&created_id)
                .await
                .expect("inspect removed ID")
                .is_none()
        );
        assert!(
            engine
                .inspect_network(&name)
                .await
                .expect("inspect removed name")
                .is_none()
        );
        assert!(
            verification.expect("inspect network"),
            "daemon normalized away the closed network contract"
        );
    }
}
